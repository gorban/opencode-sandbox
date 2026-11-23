export const VERSION = 'oc.m3a.web@1';
export const MAX_SNAPSHOT_BYTES = 32 * 1024;

const encoder = new TextEncoder();
const invalidUnicode = /[\uD800-\uDFFF]/u;
const unsafeDisplay = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu;
const statusValues = ['running', 'stopped', 'offline', 'unknown'] as const;

export type Session = { read_session_id: string; session_generation: number };
export type Entry = { label: string; text: string };
export type Thread = {
  id: string;
  label: string;
  mailbox: { text: string }[];
  provenance: Entry[];
  events: Entry[];
};
export type Sandbox = { id: string; label: string; status: typeof statusValues[number]; threads: Thread[] };
export type Project = { id: string; label: string; sandboxes: Sandbox[] };
export type Snapshot = Session & { version: typeof VERSION; projects: Project[] };

function malformed(): never {
  throw new Error('Invalid workspace response');
}

export function record(value: unknown, keys?: string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return malformed();
  if (keys && (Object.keys(value).length !== keys.length ||
      keys.some((key) => !Object.hasOwn(value, key)))) return malformed();
  return value as Record<string, unknown>;
}

function array(value: unknown, limit: number): unknown[] {
  if (!Array.isArray(value) || value.length > limit) return malformed();
  return value;
}

function token(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value)) return malformed();
  return value;
}

function display(value: unknown, check: (value: string) => boolean): string {
  if (typeof value !== 'string' || invalidUnicode.test(value) || !check(value)) return malformed();
  return value;
}

function label(value: unknown): string {
  return display(value, (text) => [...text].length <= 120)
    .replace(unsafeDisplay, '\uFFFD')
    .replace(/[\n\t]/g, '\uFFFD');
}

function body(value: unknown): string {
  return display(value, (text) => encoder.encode(text).length <= 256)
    .replaceAll('\r\n', '\n')
    .replace(unsafeDisplay, '\uFFFD');
}

function entry(value: unknown): Entry {
  const row = record(value, ['label', 'text']);
  return { label: label(row.label), text: body(row.text) };
}

function unique<T extends { id: string }>(list: T[]): T[] {
  if (new Set(list.map(({ id }) => id)).size !== list.length) return malformed();
  return list;
}

export function sessionIdentity(value: unknown): Session {
  const item = record(value);
  const generation = item.session_generation;
  if (typeof generation !== 'number' || !Number.isSafeInteger(generation) || generation <= 0) {
    return malformed();
  }
  const id = token(item.read_session_id);
  if (id.length !== 32) return malformed();
  return { read_session_id: id, session_generation: generation };
}

export function sameSession(left: Session, right: Session): boolean {
  return left.read_session_id === right.read_session_id && left.session_generation === right.session_generation;
}

export function decodeSnapshot(value: unknown): Snapshot {
  const source = record(value, ['version', 'read_session_id', 'session_generation', 'projects']);
  if (source.version !== VERSION) return malformed();
  let sandboxes = 0;
  let threads = 0;
  const projects = unique(array(source.projects, 8).map((projectValue) => {
    const project = record(projectValue, ['id', 'label', 'sandboxes']);
    return {
      id: token(project.id),
      label: label(project.label),
      sandboxes: unique(array(project.sandboxes, 16).map((sandboxValue): Sandbox => {
        const sandbox = record(sandboxValue, ['id', 'label', 'status', 'threads']);
        if (++sandboxes > 16) return malformed();
        const status = statusValues.find((value) => value === sandbox.status);
        if (!status) return malformed();
        return {
          id: token(sandbox.id),
          label: label(sandbox.label),
          status,
          threads: unique(array(sandbox.threads, 32).map((threadValue) => {
            const thread = record(threadValue, ['id', 'label', 'mailbox', 'provenance', 'events']);
            if (++threads > 32) return malformed();
            return {
              id: token(thread.id),
              label: label(thread.label),
              mailbox: array(thread.mailbox, 8).map((value) => ({ text: body(record(value, ['text']).text) })),
              provenance: array(thread.provenance, 8).map(entry),
              events: array(thread.events, 8).map(entry)
            };
          }))
        };
      }))
    };
  }));
  return { ...sessionIdentity(source), version: VERSION, projects };
}

export function cancelResponseBody(response: Response): void {
  const body = response.body;
  if (body && !body.locked && !response.bodyUsed) void body.cancel().catch(() => {});
}

export async function boundedJson(response: Response, maximum: number): Promise<unknown> {
  const mediaType = response.headers.get('content-type') ?? '';
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(mediaType) ||
      !response.body) {
    cancelResponseBody(response);
    return malformed();
  }
  const reader = response.body.getReader();
  const bytes = new Uint8Array(maximum);
  let size = 0;
  let complete = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        complete = true;
        break;
      }
      if (size + value.length > maximum) return malformed();
      bytes.set(value, size);
      size += value.length;
    }
  } finally {
    if (!complete) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size)));
}
