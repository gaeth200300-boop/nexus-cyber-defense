// Fix the two lines orphaned by dedupe-locales.mjs (remove leading orphaned values).
import { readFileSync, writeFileSync } from 'node:fs';

function fix(file, brokenPrefix, replacement) {
  const lines = readFileSync(file, 'utf8').split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(brokenPrefix)) {
      lines[i] = replacement;
      console.log(`${file}: fixed line ${i + 1}`);
    }
  }
  writeFileSync(file, lines.join('\n'));
}

// ar.ts line 192: leading orphaned value 'جارية', removed (key inProgress already exists above)
fix('src/lib/locales/ar.ts', "  'جارية', finished:", "    finished: 'منتهية'");
// ar.ts line 209: leading orphaned value removed (key rateLimited already exists above)
fix('src/lib/locales/ar.ts', "  'تم تجاوز حد المعدل', newChat:", "    newChat: 'محادثة جديدة'");
// en.ts line 192
fix('src/lib/locales/en.ts', "  'In Progress', finished:", "    finished: 'Finished'");
// en.ts line 209
fix('src/lib/locales/en.ts', "  'Rate limited', newChat:", "    newChat: 'New Chat'");
