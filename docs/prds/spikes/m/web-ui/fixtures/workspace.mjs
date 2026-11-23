export const fixtureCode = 'q'.repeat(43);

export function session(generation = 1, ttl = 60_000) {
  return {
    read_session_id: String(generation).padStart(32, 's'),
    session_generation: generation,
    csrf_token: 'c'.repeat(43),
    expires_in_ms: ttl
  };
}

export const literalText = '<b>fixture literal</b>\nhttps://example.invalid/';

export function snapshot(generation = 1) {
  const { read_session_id, session_generation } = session(generation);
  return {
    version: 'oc.m3a.web@1',
    read_session_id,
    session_generation,
    projects: [{
      id: 'synthetic-project-1',
      label: 'Fixture Workshop',
      sandboxes: [{
        id: 'synthetic-sandbox-1',
        label: 'Local build',
        status: 'running',
        threads: [{
          id: 'synthetic-thread-1',
          label: 'Build thread',
          mailbox: [{ text: literalText }],
          provenance: [{ label: 'Fixture source', text: 'Synthetic worker report' }],
          events: [{ label: 'Update', text: 'Workspace ready for review' }]
        }, {
          id: 'synthetic-thread-2',
          label: 'Review thread',
          mailbox: [], provenance: [], events: []
        }]
      }]
    }, {
      id: 'synthetic-project-2',
      label: 'Fixture Archive',
      sandboxes: [{
        id: 'synthetic-sandbox-2',
        label: 'Offline review',
        status: 'offline',
        threads: []
      }]
    }]
  };
}
