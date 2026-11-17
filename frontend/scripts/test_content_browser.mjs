/** Browser regression against the production Angular bundle, with local synthetic HTTP fixtures.
 * Run after npm run build. Uses an already installed Playwright; never downloads browsers.
 * PLAYWRIGHT_MODULE may point to an existing playwright/index.mjs; BROWSER_EXECUTABLE to Chrome.
 * This verifies browser sinks and SRI, not the separate Spring authorization/integration tests.
 */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const assets = resolve(frontend, 'dist/deep-cyber-sample-ui/browser');
const java = await readFile(resolve(frontend, '../backend/src/main/java/com/deepcyber/training/service/SupplierWidget.java'), 'utf8');
const trustedScript = JSON.parse(java.match(/TRUSTED_SCRIPT = ("[^\n]+");/)[1]);
const integrity = 'sha384-' + createHash('sha384').update(trustedScript).digest('base64');
const pinSource = await readFile(resolve(frontend, 'src/app/core/ui-policy.service.ts'), 'utf8');
assert.ok(pinSource.includes(integrity), 'Frontend pin must match immutable trusted script bytes');

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'browser-test-key', alg: 'RS256', use: 'sig' };
const marker = '<img src="/missing-note-image" onerror="document.body.dataset.northstarXss=\'seen\'">';
const tamperedScript = "document.body.dataset.northstarSupplyChain='seen';";
let revision = 'vulnerable-1';
let xssEnabled = true;
let supplyChainEnabled = true;
let policyAvailable = true;
let notes = marker;
let widget = trustedScript;
let exportRequest;
let origin;
const user = { id: 'alice', displayName: 'Alice Avery', email: 'alice.avery@aster-row.test', tenantId: 'tenant-a', organizationName: 'Aster & Row', jobTitle: 'Procurement Analyst', role: 'USER' };
const order = { id: 'ORD-A-100', tenantId: 'tenant-a', ownerId: 'alice', item: 'Laptop stand', quantity: 1, unitPrice: 49.9, status: 'DRAFT', workflowStarts: 0, version: 1 };

const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, origin).pathname;
    const json = (body, status = 200) => { response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); response.end(JSON.stringify(body)); };
    if (path === '/auth/config') return json({ issuer: origin, redirectUri: origin + '/callback', clientId: 'northstar-spa' });
    if (path === '/auth/jwks') return json({ keys: [jwk] });
    if (path === '/api/auth/me') return json(user);
    if (path === '/api/ui-policy') return json({ xssEnabled, supplyChainEnabled, revision, widgetIntegrity: integrity }, policyAvailable ? 200 : 503);
    if (path === '/api/orders/ORD-A-100') return json(order);
    if (path === '/api/orders') return json([order]);
    if (path === '/api/orders/ORD-A-100/notes') {
      if (request.method === 'PUT') { let body = ''; for await (const part of request) body += part; notes = JSON.parse(body).html; }
      return json({ orderId: order.id, html: notes });
    }
    if (path === '/api/orders/ORD-A-100/export') {
      let body = ''; for await (const part of request) body += part; exportRequest = JSON.parse(body);
      return json({ output: '<img src=x onerror="document.body.dataset.exportXss=1">', exitCode: 0, timedOut: false });
    }
    if (path === '/api/vendor/widget.js') { response.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-store' }); return response.end(widget); }
    if (path === '/missing-note-image') { response.writeHead(404); return response.end(); }
    let file = resolve(assets, '.' + path);
    if (!file.startsWith(assets + sep)) file = resolve(assets, 'index.html');
    if (!extname(path)) file = resolve(assets, 'index.html');
    const bytes = await readFile(file);
    response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' })[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    response.end(bytes);
  } catch { response.writeHead(404); response.end(); }
});
await new Promise(resolveListening => server.listen(0, '127.0.0.1', resolveListening));
origin = 'http://127.0.0.1:' + server.address().port;
const now = Math.floor(Date.now() / 1000);
const profile = { iss: origin, aud: 'northstar-spa', sub: 'alice', exp: now + 7200, iat: now };
const unsigned = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: jwk.kid })).toString('base64url') + '.' + Buffer.from(JSON.stringify(profile)).toString('base64url');
const idToken = unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url');
let browser;
try {
  browser = await chromium.launch({ headless: true, ...(process.env.BROWSER_EXECUTABLE ? { executablePath: process.env.BROWSER_EXECUTABLE } : {}) });
  const context = await browser.newContext();
  await context.addInitScript(({ origin, profile, idToken, now }) => {
    sessionStorage.setItem('oidc.user:' + origin + ':northstar-spa', JSON.stringify({ id_token: idToken, access_token: 'synthetic-browser-test-token', token_type: 'Bearer', scope: 'openid profile northstar.api', profile, expires_at: now + 7200 }));
  }, { origin, profile, idToken, now });
  const page = await context.newPage();
  await page.goto(origin + '/orders/ORD-A-100');
  await page.waitForFunction(() => document.body.dataset.northstarXss === 'seen');
  assert.equal(await page.locator('[data-testid="purchasing-notes"] img').getAttribute('onerror'), "document.body.dataset.northstarXss='seen'");
  await page.waitForFunction(() => document.getElementById('northstar-supplier-widget')?.textContent.includes('Standard delivery'));
  assert.equal(await page.locator('script[src*="/api/vendor/widget.js"]').getAttribute('integrity'), null);
  console.log('PASS: vulnerable Angular trust bypass executes harmless stored marker; unpinned supplier widget loads');

  widget = tamperedScript;
  await page.reload();
  await page.waitForFunction(() => document.body.dataset.northstarSupplyChain === 'seen');
  console.log('PASS: lab-owned supplier tampering executes in vulnerable mode');

  xssEnabled = false; supplyChainEnabled = false; revision = 'fixed-2';
  await page.waitForFunction(() => document.querySelector('script[src*="/api/vendor/widget.js"]')?.integrity?.startsWith('sha384-'), null, { timeout: 12000 });
  await page.waitForFunction(() => document.getElementById('northstar-supplier-widget')?.textContent.includes('could not be verified'));
  assert.equal(await page.evaluate(() => document.body.dataset.northstarXss), undefined);
  assert.equal(await page.evaluate(() => document.body.dataset.northstarSupplyChain), undefined);
  assert.equal(await page.locator('[data-testid="purchasing-notes"] img').getAttribute('onerror'), null);
  console.log('PASS: live fixed switch reloads context, Angular strips event handlers, SRI rejects tampered bytes');

  widget = trustedScript;
  await page.reload();
  await page.waitForFunction(() => document.getElementById('northstar-supplier-widget')?.textContent.includes('Standard delivery'));
  assert.equal(await page.locator('script[src*="/api/vendor/widget.js"]').getAttribute('integrity'), integrity);
  await page.getByLabel('Edit formatted notes').fill('<b>Updated purchasing notes</b>');
  await page.getByRole('button', { name: 'Save notes' }).click();
  await page.waitForFunction(() => document.querySelector('[data-testid="purchasing-notes"] b')?.textContent === 'Updated purchasing notes');
  await page.getByLabel('Export format').fill('csv; printf marker');
  await page.getByRole('button', { name: 'Generate export' }).click();
  await page.locator('.export-output').waitFor();
  assert.deepEqual(exportRequest, { format: 'csv; printf marker' });
  assert.equal(await page.evaluate(() => document.body.dataset.exportXss), undefined);
  assert.match(await page.locator('.export-output').textContent(), /<img/);
  console.log('PASS: trusted fixed widget passes SRI, note editing works, export output is escaped text');

  notes = marker; policyAvailable = false;
  await page.reload();
  await page.locator('[data-testid="purchasing-notes"] img').waitFor();
  assert.equal(await page.locator('[data-testid="purchasing-notes"] img').getAttribute('onerror'), null);
  assert.equal(await page.locator('script[src*="/api/vendor/widget.js"]').count(), 0);
  assert.equal(await page.evaluate(() => document.body.dataset.northstarXss), undefined);
  console.log('PASS: unavailable policy fails fixed and does not load any supplier script');
} finally {
  await browser?.close();
  await new Promise(resolveClosed => server.close(resolveClosed));
}
