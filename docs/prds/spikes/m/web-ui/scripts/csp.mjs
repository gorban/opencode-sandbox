import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

// The pinned adapter emits this fixed shell. Requalify if its structure changes.
const headStart = /^<!doctype html>\s*<html lang="en">\s*<head>/u;
const shellEnd = /<\/head>\s*<body>\s*<div id="app">\s*<script>(.+)<\/script>\s*<\/div>\s*<\/body>\s*<\/html>\s*$/su;
const assetLink = /^<link href="\/_app\/immutable\/[A-Za-z0-9_./-]+(?:\.js" rel="modulepreload"|\.css" rel="stylesheet")>$/u;

function validHead(head) {
  const [charset, viewport, title, ...links] = head.trim().split(/(?<=>)\s*(?=<)/u);
  return charset === '<meta charset="utf-8">' &&
    viewport === '<meta name="viewport" content="width=device-width, initial-scale=1">' &&
    title === '<title>Workspace dashboard</title>' &&
    links.every((link) => assetLink.test(link));
}

export function manifest(bytes) {
  const html = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  if (/[\r\0]/.test(html)) throw new Error('Unsupported fallback line endings or NUL');
  const head = headStart.exec(html);
  const end = shellEnd.exec(html);
  if (!head || !end || !validHead(html.slice(head[0].length, end.index)) ||
      /<\/?script\b|<!--/i.test(end[1])) throw new Error('Unsupported fallback shell');
  const body = end[1];

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
