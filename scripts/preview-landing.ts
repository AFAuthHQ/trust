// Dev-only: serve the marketing pages on localhost for visual review,
// without the full server's Postgres/Redis/KEK boot. Run with:
//   npx tsx scripts/preview-landing.ts
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { landingPage } from '../src/views/landing.js';
import { developersPage } from '../src/views/developers.js';
import { operatorPage } from '../src/views/operator.js';
import { policyPage } from '../src/views/policy.js';
import { layout } from '../src/views/layout.js';

const app = new Hono();

app.get('/', async (c) =>
  c.html(await layout({ title: 'trust.afauth.org', path: '/', body: landingPage() })),
);
app.get('/developers', async (c) =>
  c.html(await layout({ title: 'For service developers · trust.afauth.org', path: '/developers', body: developersPage() })),
);
app.get('/operator', async (c) =>
  c.html(await layout({ title: 'Operator commitment · trust.afauth.org', path: '/operator', body: operatorPage() })),
);
app.get('/policy', async (c) =>
  c.html(await layout({ title: 'Take-down policy · trust.afauth.org', path: '/policy', body: policyPage() })),
);
app.use('/favicon.svg', serveStatic({ path: './public/favicon.svg' }));

const port = Number(process.env.PREVIEW_PORT ?? 4040);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`preview → http://localhost:${info.port}/`);
});
