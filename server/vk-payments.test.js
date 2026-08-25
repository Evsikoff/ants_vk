'use strict';

/* Tests for what is left of the payment service after the key check came out of the
   purchase flow. The game no longer calls this file at all — it grants on
   VKWebAppShowOrderBox's own `success` — so what is tested here is the one endpoint
   VK itself calls: pricing the dialog, and keeping an honest, idempotent ledger of
   what was charged. */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const APP_ID = '6736218';
const APP_SECRET = 'wvl68m4dR1UpLrVRli';
const USER_ID = '494075';
const storeFile = path.join(os.tmpdir(), `ants-vk-payments-${process.pid}.json`);

process.env.VK_APP_ID = APP_ID;
process.env.VK_APP_SECRET = APP_SECRET;
process.env.VK_STORE = storeFile;

try { fs.unlinkSync(storeFile); } catch (_) {}

const { handleCallback, store, CFG } = require('./vk-payments');

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

function sign(params) {
  const base = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('');
  return crypto.createHash('md5').update(base + APP_SECRET, 'utf8').digest('hex');
}

function paymentParams(extra) {
  const params = {
    notification_type: 'order_status_change_test',
    app_id: APP_ID,
    user_id: USER_ID,
    receiver_id: '1',
    order_id: '1001',
    item: 'ants_lives_refill',
    item_price: '1',
    status: 'chargeable',
    ...extra
  };
  params.sig = sign(params);
  return params;
}

test('get_item prices the dialog from the catalogue', () => {
  const params = { notification_type: 'get_item_test', app_id: APP_ID, user_id: USER_ID, item: 'ants_no_ads' };
  params.sig = sign(params);
  const priced = response();
  handleCallback(params, priced);
  assert.equal(priced.json().response.item_id, 'ants_no_ads');
  assert.equal(priced.json().response.price, 20);
});

test('an unknown item is rejected instead of guessed at', () => {
  const params = { notification_type: 'get_item_test', app_id: APP_ID, user_id: USER_ID, item: 'nope' };
  params.sig = sign(params);
  const res = response();
  handleCallback(params, res);
  assert.equal(res.json().error.error_code, 20);
  assert.equal(res.json().error.critical, true);
});

test('confirmed orders are durable and idempotent', () => {
  const first = response();
  handleCallback(paymentParams(), first);
  assert.equal(first.status, 200);
  assert.equal(first.json().response.order_id, 1001);

  const duplicate = response();
  handleCallback(paymentParams(), duplicate);
  assert.equal(duplicate.json().response.order_id, 1001);
  assert.equal(store.countFor(USER_ID, 'ants_lives_refill'), 1);
  assert.equal(store.getOrder('1001').status, 'confirmed');
});

test('each consumable order has its own id and refunds leave it in the ledger', () => {
  const second = response();
  handleCallback(paymentParams({ order_id: '1002' }), second);
  assert.equal(store.countFor(USER_ID, 'ants_lives_refill'), 2);

  const refunded = response();
  handleCallback(paymentParams({ order_id: '1002', status: 'refunded' }), refunded);
  assert.equal(refunded.json().response.order_id, 1002);
  assert.equal(store.countFor(USER_ID, 'ants_lives_refill'), 1);
  assert.equal(store.getOrder('1002').status, 'refunded');
});

test('a bad signature is refused while a secret is configured', () => {
  const res = response();
  handleCallback(paymentParams({ order_id: '1003', sig: 'deadbeef' }), res);
  assert.equal(res.json().error.error_code, 10);
  assert.equal(store.seenOrder('1003'), false);
});

/* The point of making the secret optional: a key that was never configured must not
   be able to take the storefront down, because VK prices the dialog from get_item. */
test('with no secret configured the callback still prices and records', t => {
  const old = CFG.appSecret;
  CFG.appSecret = '';
  t.after(() => { CFG.appSecret = old; });

  const priced = response();
  handleCallback({ notification_type: 'get_item_test', app_id: APP_ID, user_id: USER_ID, item: 'ants_lives_refill' }, priced);
  assert.equal(priced.json().response.price, 1);

  const charged = response();
  handleCallback({
    notification_type: 'order_status_change_test', app_id: APP_ID, user_id: USER_ID,
    receiver_id: '1', order_id: '1004', item: 'ants_lives_refill', item_price: '1', status: 'chargeable'
  }, charged);
  assert.equal(charged.json().response.order_id, 1004);
  assert.equal(store.seenOrder('1004'), true);
});

test.after(() => {
  try { fs.unlinkSync(storeFile); } catch (_) {}
});
