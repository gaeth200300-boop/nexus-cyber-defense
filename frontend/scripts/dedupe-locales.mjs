// Removes duplicate keys from locale files, keeping the last occurrence.
import { readFileSync, writeFileSync } from 'node:fs';

const files = ['src/lib/locales/ar.ts', 'src/lib/locales/en.ts'];
const re = /^(\s*)(?:([A-Za-z_][A-Za-z0-9_]*)|(['"])([^'"]+)\3):/gm;

function dedup(f) {
  let s = readFileSync(f, 'utf8');
  const seen = new Map();
  const matches = [];
  let m;
  re.lastIndex = 0;
  while ((m = re.exec(s)) !== null) {
    const key = m[2] || m[4];
    if (seen.has(key)) {
      const prev = seen.get(key);
      s = s.slice(0, prev.start) + s.slice(prev.end);
      writeFileSync(f, s);
      return dedup(f);
    }
    seen.set(key, { start: m.index, end: m.index + m[0].length });
  }
  writeFileSync(f, s);
  console.log(f, 'ok, unique keys:', seen.size);
}

for (const f of files) dedup(f);
