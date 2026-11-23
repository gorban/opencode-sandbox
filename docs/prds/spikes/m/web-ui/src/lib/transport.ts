import { boundedJson, cancelResponseBody, decodeSnapshot, MAX_SNAPSHOT_BYTES, record, sessionIdentity } from './projection.ts';
import type { Session, Snapshot } from './projection.ts';

const MAX_AUTH_BYTES = 4 * 1024;

export type AuthReply = Session & { csrf_token: string; expires_in_ms: number };
export type Signal = 'refresh' | 'session-ended';

export interface Transport {
  session(signal: AbortSignal): Promise<AuthReply>;
  exchange(code: string): Promise<AuthReply>;
  logout(csrf: string): Promise<void>;
  load(signal: AbortSignal): Promise<Snapshot>;
  subscribe(signal: AbortSignal, callback: (event: Signal) => void): () => void;
}

export class Denied extends Error {}
export class InvalidCode extends Error {}

function decodeAuth(value: unknown): AuthReply {
  const reply = record(value, ['read_session_id', 'session_generation', 'csrf_token', 'expires_in_ms']);
  const csrf = reply.csrf_token;
  const remaining = reply.expires_in_ms;
  if (typeof csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(csrf) ||
      typeof remaining !== 'number' || !Number.isSafeInteger(remaining) || remaining <= 0 ||
      remaining > 1_800_000) throw new Error('Invalid session response');
  return { ...sessionIdentity(reply), csrf_token: csrf, expires_in_ms: remaining };
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(path, {
    ...init,
    mode: 'same-origin',
    credentials: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    headers: { 'X-OC-UI': '1', ...init.headers }
  });
}

function requireSuccess(response: Response, status: number): void {
  if (response.status === status) return;
  cancelResponseBody(response);
  if ([401, 403].includes(response.status)) throw new Denied();
  throw new Error('Request did not complete');
}

export function browserTransport(): Transport {
  return {
    async session(signal) {
      const response = await request('/api/auth/session', { signal });
      requireSuccess(response, 200);
      return decodeAuth(await boundedJson(response, MAX_AUTH_BYTES));
    },
    async exchange(code) {
      const response = await request('/api/auth/exchange', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      if (response.status === 401) {
        cancelResponseBody(response);
        throw new InvalidCode();
      }
      requireSuccess(response, 200);
      return decodeAuth(await boundedJson(response, MAX_AUTH_BYTES));
    },
    async logout(csrf) {
      const response = await request('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-OC-CSRF': csrf }
      });
      requireSuccess(response, 204);
    },
    async load(signal) {
      const response = await request('/api/v1/workspace', { signal });
      requireSuccess(response, 200);
      return decodeSnapshot(await boundedJson(response, MAX_SNAPSHOT_BYTES));
    },
    subscribe() {
      return () => {};
    }
  };
}
