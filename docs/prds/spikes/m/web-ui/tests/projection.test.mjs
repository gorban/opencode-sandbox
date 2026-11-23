import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { snapshot } from '../fixtures/workspace.mjs';
import { manifest } from '../scripts/csp.mjs';
import { boundedJson, decodeSnapshot } from '../src/lib/projection.ts';

test('manifest matches fixture bytes and rejects unsupported HTML', async () => {
  const bytes = await readFile(new URL('../fixtures/bootstrap.html', import.meta.url));
  const expected = JSON.parse(await readFile(new URL('../fixtures/csp-manifest.json', import.meta.url)));
  assert.deepEqual(manifest(bytes), expected);
  const html = bytes.toString();
  for (const changed of [
    html.replace('café', 'caf\u0000'),
    html.replace('café', 'caf\r'),
    html.replace('</script>', '</script><script>2</script>'),
    html.replace('document.documentElement', '<!-- document.documentElement'),
    html.replace(/<script>[^]*<\/script>/u, '<script></script>'),
    html.replace('<title>', '<title>duplicate</title><title>'),
    html.replace('<title>', '<title data-extra="value">'),
    html.replace('</head>', '<link href="/_app/immutable/bad.css" rel="modulepreload"></head>'),
    html.replace('</head>', '<link href="https://example.invalid/style.css" rel="stylesheet"></head>'),
    html.replace('<div id="app">', '<div id="app" style="color:red">'),
    html.replace('<div id="app">', '<div id="app" onclick="f()">'),
    html.replace('<head>', '<head><meta http-equiv="refresh">'),
    html.replace('<head>', '<head><base href="/">')
  ]) assert.throws(() => manifest(Buffer.from(changed)));
  const linked = html.replace('</head>', [
    '<link href="/_app/immutable/entry/start.abc.js" rel="modulepreload">',
    '<link href="/_app/immutable/assets/navigation.def.css" rel="stylesheet">',
    '</head>'
  ].join(''));
  assert.equal(manifest(Buffer.from(linked)).inline_script_sha256, expected.inline_script_sha256);
  const invalidUtf8 = Buffer.from(bytes);
  invalidUtf8[html.indexOf('café')] = 0xff;
  assert.throws(() => manifest(invalidUtf8));
  assert.notEqual(manifest(Buffer.from(html.replace('café', 'coffee'))).html_sha256, expected.html_sha256);
});

test('workspace decoder enforces own keys, counts, encodings and bounded text', () => {
  assert.deepEqual(decodeSnapshot(snapshot()), snapshot());
  for (const mutate of [
    (data) => { data.version = 'unknown'; },
    (data) => { data.read_session_id = ' '; },
    (data) => { data.projects[0].id = 'label with space'; },
    (data) => { data.projects.unshift(data.projects[0]); },
    (data) => { data.projects[0].constructor = 1; },
    (data) => { Object.defineProperty(data.projects[0], '__proto__', { value: null, enumerable: true }); },
    (data) => { data.projects[0].sandboxes[0].status = 'self-reported'; },
    (data) => { data.projects[0].sandboxes[0].threads[0].mailbox[0].text = 'é'.repeat(129); },
    (data) => { data.projects[0].label = '\ud800'; },
    (data) => { data.projects[0].label = '🌲'.repeat(121); },
    (data) => { data.projects[0].sandboxes = Array.from({ length: 16 }, (_, i) => ({
      ...data.projects[0].sandboxes[0], id: String(i)
    })); }
  ]) {
    const invalid = snapshot();
    mutate(invalid);
    assert.throws(() => decodeSnapshot(invalid));
  }
});

test('display labels and bodies normalize controls separately', () => {
  const input = snapshot();
  input.projects[0].label = 'a\r\n\t\u202eb';
  input.projects[0].sandboxes[0].threads[0].mailbox[0].text = 'a\r\nb\rc\u0000\u0085\u202e';
  const [project] = decodeSnapshot(input).projects;
  assert.equal(project.label, 'a\uFFFD\uFFFD\uFFFD\uFFFDb');
  assert.equal(project.sandboxes[0].threads[0].mailbox[0].text, 'a\nb\uFFFDc\uFFFD\uFFFD\uFFFD');
});

test('JSON reader rejects untrusted media, bad UTF-8 and excess streamed bytes', async () => {
  const headers = { 'Content-Type': 'application/json; charset=utf-8' };
  assert.deepEqual(await boundedJson(new Response('[]', { headers }), 2), []);
  await assert.rejects(boundedJson(new Response('{}'), 2));
  await assert.rejects(boundedJson(new Response(Uint8Array.of(0xff), { headers }), 2));
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(Uint8Array.of(91, 93));
      controller.enqueue(Uint8Array.of(32));
    }
  });
  await assert.rejects(boundedJson(new Response(stream, { headers }), 2));
});
