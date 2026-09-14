import { build } from 'esbuild';
await build({entryPoints:['src/index.ts'],outfile:'dist/browser.js',bundle:true,format:'esm',
  platform:'browser',target:['es2022'],legalComments:'eof',minify:false});
