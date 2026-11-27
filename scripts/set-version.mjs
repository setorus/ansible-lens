#!/usr/bin/env node
// Writes one version into every place the site reads it from.
// Usage: node scripts/set-version.mjs 1.2.3
import { readFileSync, writeFileSync } from "node:fs";

const v = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(v || "")) {
  console.error(`invalid version: ${v}`);
  process.exit(1);
}

const edits = [
  // app version; also busts worker.js / example.json / lens/*.py caches
  ["assets/app.js", /(const VERSION = ")[^"]+(";)/, `$1${v}$2`],
  // cache-busting query on the page's own css/js
  ["index.html", /(\?v=)[0-9A-Za-z.+-]+/g, `$1${v}`],
  ["lens/__init__.py", /(__version__ = ")[^"]+(")/, `$1${v}$2`],
];

for (const [file, re, rep] of edits) {
  const src = readFileSync(file, "utf8");
  const out = src.replace(re, rep);
  if (out === src && !src.includes(v)) {
    console.error(`${file}: version pattern not found`);
    process.exit(1);
  }
  writeFileSync(file, out);
  console.log(`${file} -> ${v}`);
}
