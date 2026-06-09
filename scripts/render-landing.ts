// Dev-only: render the landing page to a static HTML file for visual review,
// without booting the server (no Postgres/Redis needed). Run with:
//   npx tsx scripts/render-landing.ts
import { writeFileSync } from 'node:fs';
import { landingPage } from '../src/views/landing.ts';
import { layout } from '../src/views/layout.ts';

const out = await layout({
  title: 'trust.afauth.org',
  path: '/',
  body: landingPage(),
});

const dest = '/tmp/trust-landing.html';
writeFileSync(dest, String(out));
console.log(`wrote ${dest}`);
