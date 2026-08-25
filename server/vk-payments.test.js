'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const APP_ID = '6736218';
const APP_SECRET = 'wvl68m4dR1UpLrVRli';
const storeFile = path.join(os.tmpdir(), `ants-vk-payments-${process.pid}.json`);

process.env.VK_APP_ID = APP_ID;
process.env.VK_APP_SECRET = APP_SECRET;
process.env.VK_STORE = storeFile;
process.env.VK_ALLOWED_ORIGINS = 'https://game.example';

try { fs.unlinkSync(storeFile); } catch (_) {}

const {
  handleCallback,
  handleVerify,
  launchSignOK,
  store,
  server,
  CFG
} = require('./vk-payments');

const launch = Object.fromEntries(new URL(
  'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1' +
  '&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=' +
  '&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA'
).searchParams);

function response() {
  return {
    status: 0,
    headers: {},
    body: '',
    setHeader(k, v) { this.headers[k] = v; },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers || {}); },
    end(body) { this.body = body ? Buffer.from(body).toString('utf8') : ''; },
    json() { return JSON.parse(this.body); }
  };
}

function paymentParams(extra) {
  const params = {
    notification_type: 'order_status_change_test',
    app_id: APP_ID,
    user_id: launch.vk_user_id,
    receiver_id: '1',
    order_id: '1001',
    item: 'ants_lives_refill',
    item_price: '1',
    status: 'chargeable',
    ...extra
  };
  const base = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('');
  params.sig = crypto.createHash('md5').update(base + APP_SECRET, 'utf8').digest('hex');
  return params;
}

test('launch params use the protected app secret', () => {
  assert.equal(launchSignOK(launch), true);
});

test('confirmed orders are durable, idempotent and returned by /vk/verify', () => {
  const first = response();
  handleCallback(paymentParams(), first);
  assert.equal(first.status, 200);
  assert.equal(first.json().response.order_id, 1001);

  const duplicate = response();
  handleCallback(paymentParams(), duplicate);
  assert.equal(duplicate.json().response.order_id, 1001);
  assert.equal(store.ordersFor(launch.vk_user_id).length, 1);
  assert.equal(store.all(launch.vk_user_id).ants_lives_refill, 1);

  const verify = response();
  handleVerify(JSON.stringify({ item: 'ants_lives_refill', launch }), verify);
  const payload = verify.json();
  assert.equal(payload.granted, true);
  assert.equal(payload.status, 'confirmed');
  assert.deepEqual(payload.orders.map(o => o.order_id), ['1001']);
});

test('each consumable order has its own id and refunds leave it in the ledger', () => {
  const second = response();
  handleCallback(paymentParams({ order_id: '1002' }), second);
  assert.equal(store.all(launch.vk_user_id).ants_lives_refill, 2);

  const refunded = response();
  handleCallback(paymentParams({ order_id: '1002', status: 'refunded' }), refunded);
  assert.equal(refunded.json().response.order_id, 1002);
  assert.equal(store.all(launch.vk_user_id).ants_lives_refill, 1);
  assert.equal(store.getOrder('1002').status, 'refunded');
  assert.deepEqual(store.ordersFor(launch.vk_user_id).map(o => o.status), ['confirmed', 'refunded']);
});

test('same-origin verification works without a CORS allowlist', async t => {
  const old = CFG.allowedOrigins.slice();
  CFG.allowedOrigins.length = 0;
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  t.after(() => CFG.allowedOrigins.push(...old));

  const port = server.address().port;
  const result = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: '/vk/verify', method: 'OPTIONS',
      headers: { Host: 'game.example', Origin: 'https://game.example' }
    }, res => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, origin: res.headers['access-control-allow-origin'] }));
    });
    req.on('error', reject); req.end();
  });

  assert.equal(result.status, 204);
  assert.equal(result.origin, 'https://game.example');
});

test.after(() => {
  try { fs.unlinkSync(storeFile); } catch (_) {}
});
