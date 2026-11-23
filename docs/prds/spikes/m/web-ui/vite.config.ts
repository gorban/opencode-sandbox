import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, normalizePath } from 'vite';
import type { Plugin } from 'vite';

const ROOT_COMPONENT_SHA256 = '26acca1c521c771906deea7475985544445cccb6ee0d2a150a68ed6fc6d5fad9';
const ANNOUNCER_DECLARATION = /(id="svelte-announcer"\s+aria-live="assertive"\s+aria-atomic="true")\s+style="([^"]+)"/g;

function compileAnnouncerCss(): Plugin {
  let rootComponent: string;
  let clientTransformed = false;

  return {
    name: 'compile-kit-announcer-css',
    enforce: 'pre',
    configResolved(config) {
      rootComponent = normalizePath(resolve(config.root,
        'node_modules/@sveltejs/kit/src/runtime/components/root.svelte'));
    },
    transform(code, id) {
      if (id !== rootComponent || this.environment.name !== 'client') return;
      const digest = createHash('sha256').update(code).digest('hex');
      const matches = [...code.matchAll(ANNOUNCER_DECLARATION)];
      if (digest !== ROOT_COMPONENT_SHA256 || matches.length !== 1) {
        this.error('SvelteKit root component changed. Requalify its announcer under CSP.');
      }

      const [attribute, aria, declaration] = matches[0];
      clientTransformed = true;
      return code.replace(attribute, aria) + `\n<style>\n\t#svelte-announcer { ${declaration} }\n</style>\n`;
    },
    buildEnd(error) {
      if (!error && this.environment.name === 'client' && !clientTransformed) {
        this.error('Missing SvelteKit announcer CSS transformation');
      }
    }
  };
}

export default defineConfig({
  plugins: [
    compileAnnouncerCss(),
    sveltekit({
      adapter: adapter({ fallback: '200.html' }),
      inlineStyleThreshold: 0,
      paths: { relative: false }
    })
  ]
});
