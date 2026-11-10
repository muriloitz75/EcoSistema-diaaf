// Pré-compila o script.js (JSX) para dist/app.js, eliminando o Babel no navegador.
// Executado automaticamente pelo Railway no build (npm run build).
const esbuild = require('esbuild');
const path = require('path');

const root = path.join(__dirname, '..');
const start = Date.now();

esbuild.buildSync({
    entryPoints: [path.join(root, 'script.js')],
    outfile: path.join(root, 'dist', 'app.js'),
    loader: { '.js': 'jsx' },
    jsx: 'transform',          // React.createElement (mesmo do Babel "classic")
    format: 'iife',            // isola o escopo, como o new Function() fazia
    target: 'es2019',
    minify: true,
    sourcemap: true,
    legalComments: 'none',
    logLevel: 'warning',
});

console.log(`[build] dist/app.js gerado em ${Date.now() - start}ms`);
