// Rebuilds locale files by parsing key:value pairs, deduplicating (last wins),
// and writing clean output. Handles multi-line values minimally — our values are
// single-line strings ending with a comma or closing brace.
import { readFileSync, writeFileSync } from 'node:fs';

for (const f of ['src/lib/locales/ar.ts', 'src/lib/locales/en.ts']) {
  const src = readFileSync(f, 'utf8');
  // Extract the body between "translation: {" and the final "};"
  const start = src.indexOf('{');
  const end = src.lastIndexOf('}');
  const body = src.slice(start + 1, end);
  const map = new Map();
  const re = /([A-Za-z_][A-Za-z0-9_]*):\s*'((?:[^'\\]|\\.)*)'/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    map.set(m[1], m[2]);
  }
  const header = "export const ar = {\n  translation: {\n";
  const headerEn = "export const en = {\n  translation: {\n";
  const isAr = f.includes('/ar.');
  let out = (isAr ? header : headerEn);
  const keys = [...map.keys()];
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    const v = map[k];
    out += `    ${k}: '${v}'${i < keys.length - 1 ? ',' : ''}\n`;
  }
  out += '  },\n};\n';
  writeFileSync(f, out);
  console.log(f, 'keys:', keys.length);
}
