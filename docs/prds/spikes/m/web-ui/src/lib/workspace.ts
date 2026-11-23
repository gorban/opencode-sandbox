import { sameSession } from './projection.ts';
import type { Snapshot } from './projection.ts';
import { Denied, InvalidCode } from './transport.ts';
import type { AuthReply, Transport } from './transport.ts';

export type View = {
  phase: 'checking' | 'signed-out' | 'loading' | 'ready' | 'error';
  snapshot: Snapshot | null;
  message: string;
  authBusy: boolean;
  authBlocked: boolean;
  canLogout: boolean;
};

type Clock = { monotonic(): number; wall(): number };
type Started = { monotonic: number; wall: number };
type Lease = {
  reply: AuthReply;
  started: Started;
  lastWall: number;
  abort: AbortController;
  unsubscribe: () => void;
};

const MAX_EXPIRY_WAKE_MS = 1000;

const clock: Clock = { monotonic: () => performance.now(), wall: () => Date.now() };

export class Workspace {
  private sessionCheck: AbortController | null = null;
  private request: AbortController | null = null;
  private lease: Lease | null = null;
  private generation = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private suspended = false;
  private mutation = false;
  private blocked = false;
  private view: View = {
    phase: 'checking', snapshot: null, message: 'Checking session',
    authBusy: false, authBlocked: false, canLogout: false
  };

  private readonly transport: Transport;
  private readonly publish: (view: View) => void;
  private readonly time: Clock;

  constructor(transport: Transport, publish: (view: View) => void, time: Clock = clock) {
    this.transport = transport;
    this.publish = publish;
    this.time = time;
  }

  private started(): Started {
    return { monotonic: this.time.monotonic(), wall: this.time.wall() };
  }

  private update(phase: View['phase'], message: string, snapshot: Snapshot | null = null): void {
    this.view = {
      phase, snapshot, message, authBusy: this.mutation,
      authBlocked: this.blocked, canLogout: this.lease !== null
    };
    this.publish(this.view);
  }

  private retire(phase: View['phase'], message: string): void {
    ++this.generation;
    const lease = this.lease;
    this.lease = null;
    this.sessionCheck?.abort();
    this.sessionCheck = null;
    this.request?.abort();
    this.request = null;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    lease?.abort.abort();
    lease?.unsubscribe();
    this.update(phase, message);
  }

  suspend(): void {
    this.suspended = true;
    this.retire('checking', 'Session paused');
  }

  async resume(): Promise<void> {
    this.suspended = false;
    if (this.mutation) return;
    if (this.blocked) {
      this.retire('signed-out', 'Start a fresh browser profile and reset the host to sign in.');
      return;
    }

    this.retire('checking', 'Checking session');
    const generation = this.generation;
    const check = new AbortController();
    this.sessionCheck = check;
    const started = this.started();
    try {
      const reply = await this.transport.session(check.signal);
      if (this.generation === generation) this.install(reply, started);
    } catch (error) {
      if (this.generation === generation) {
        this.retire('signed-out', error instanceof Denied ? 'Signed out' : 'Unable to check session');
      }
    } finally {
      if (this.sessionCheck === check) this.sessionCheck = null;
    }
  }

  async exchange(code: string): Promise<void> {
    if (this.mutation || this.blocked || this.suspended || this.view.phase !== 'signed-out') return;
    if (!/^[A-Za-z0-9_-]{43}$/.test(code)) {
      this.update('signed-out', 'Enter a valid one-use code');
      return;
    }
    this.mutation = true;
    this.retire('signed-out', 'Signing in');
    const generation = this.generation;
    const started = this.started();
    let reply: AuthReply | undefined;
    let message = 'Signed out';
    try {
      reply = await this.transport.exchange(code);
    } catch (error) {
      if (error instanceof InvalidCode) message = 'Code expired or invalid';
      else {
        this.blocked = true;
        message = 'Sign-in could not be confirmed. Reset the host and use a fresh browser profile.';
      }
    } finally {
      this.mutation = false;
    }

    if (reply && this.generation === generation) this.install(reply, started);
    else if (reply && !this.suspended) await this.resume();
    else this.update('signed-out', message);
  }

  async logout(): Promise<void> {
    if (this.mutation || !this.lease) return;
    const csrf = this.lease.reply.csrf_token;
    this.mutation = true;
    this.retire('signed-out', 'Signing out');
    let message = 'Signed out';
    try {
      await this.transport.logout(csrf);
    } catch {
      this.blocked = true;
      message = 'Sign-out could not be confirmed. Reset the host and use a fresh browser profile.';
    } finally {
      this.mutation = false;
      this.update('signed-out', message);
    }
  }

  private remaining(lease: Lease): number {
    const wall = this.time.wall();
    const monotonic = this.time.monotonic();
    if (!Number.isFinite(wall) || !Number.isFinite(monotonic) ||
        wall < lease.lastWall || monotonic < lease.started.monotonic) return 0;
    lease.lastWall = wall;
    return lease.reply.expires_in_ms - Math.max(
      monotonic - lease.started.monotonic,
      wall - lease.started.wall
    );
  }

  private install(reply: AuthReply, started: Started): void {
    const lease: Lease = {
      reply, started, lastWall: started.wall, abort: new AbortController(), unsubscribe: () => {}
    };
    if (this.suspended || this.remaining(lease) <= 0) {
      this.retire('signed-out', 'Session expired');
      return;
    }

    this.lease = lease;
    lease.unsubscribe = this.transport.subscribe(lease.abort.signal, (event) => {
      if (this.lease !== lease) return;
      if (event === 'session-ended') this.retire('signed-out', 'Session expired');
      else void this.refresh();
    });
    if (this.lease !== lease) {
      lease.unsubscribe();
      return;
    }

    const scheduleExpiry = () => {
      if (this.lease !== lease) return;
      const remaining = this.remaining(lease);
      if (remaining <= 0) this.retire('signed-out', 'Session expired');
      else this.timer = setTimeout(scheduleExpiry, Math.min(remaining, MAX_EXPIRY_WAKE_MS));
    };
    scheduleExpiry();
    if (!this.request) void this.refresh();
  }

  async refresh(): Promise<void> {
    const lease = this.lease;
    if (!lease) return;
    if (this.remaining(lease) <= 0) {
      this.retire('signed-out', 'Session expired');
      return;
    }

    this.request?.abort();
    const request = new AbortController();
    this.request = request;
    this.update('loading', 'Loading workspace');
    try {
      const snapshot = await this.transport.load(request.signal);
      if (this.lease !== lease || this.request !== request) return;
      if (!sameSession(snapshot, lease.reply) || this.remaining(lease) <= 0) {
        this.retire('signed-out', 'Session changed or expired');
        return;
      }
      this.update('ready', snapshot.projects.length ? 'Workspace ready' : 'No projects', snapshot);
    } catch (error) {
      if (this.lease !== lease || this.request !== request) return;
      if (error instanceof Denied || this.remaining(lease) <= 0) {
        this.retire('signed-out', 'Session changed or expired');
      } else this.update('error', 'Workspace unavailable');
    } finally {
      if (this.request === request) this.request = null;
    }
  }
}
