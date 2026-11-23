import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

// The pinned adapter emits this fixed shell. Requalify if its structure changes.
const shell = /^<!doctype html>\s*<html lang="en">\s*<head>\s*<meta charset="utf-8">\s*<meta name="viewport" content="width=device-width, initial-scale=1">\s*(?:<link href="\/_app\/immutable\/[A-Za-z0-9_./-]+(?:\.js" rel="modulepreload"|\.css" rel="stylesheet")>\s*)*<\/head>\s*<body>\s*<div id="app">\s*<script>([\s\S]+)<\/script>\s*<\/div>\s*<\/body>\s*<\/html>\s*$/u;

export function manifest(bytes) {
  const html = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  if (/[\r\0]/.test(html)) throw new Error('Unsupported fallback line endings or NUL');
  const match = shell.exec(html);
  const body = match?.[1];
  if (!body || /<\/?script\b|<!--/i.test(body)) throw new Error('Unsupported fallback shell');

  // Strict UTF-8 and LF-only input make its decoded span round-trip byte-for-byte.
  const start = Buffer.byteLength(html.slice(0, html.indexOf('<script>') + '<script>'.length));
  const span = bytes.subarray(start, start + Buffer.byteLength(body));
  return {
    version: 1,
    html_sha256: createHash('sha256').update(bytes).digest('hex'),
    inline_script_sha256: createHash('sha256').update(span).digest('base64')
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const output = new URL('../build/', import.meta.url);
  const contents = await readFile(new URL('200.html', output));
  await writeFile(fileURLToPath(new URL('csp-manifest.json', output)),
    JSON.stringify(manifest(contents), null, 2) + '\n');
}
