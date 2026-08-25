/* =============================================================================
   VK PAYMENTS CALLBACK — server/vk-payments.js

   ---- WHAT THIS IS, AFTER THE KEY CHECK CAME OUT ----
   The game grants purchases IN THE PAGE, on VKWebAppShowOrderBox's own
   `{status:'success'}` — that is the flow the official documentation describes, and
   it needs no signature, no launch-param HMAC and no verification round trip. The
   client used to refuse to open the payment dialog until a backend had verified the
   launch `sign`; that is what made purchases fail whenever the backend was absent,
   unreachable or configured with the wrong key, and it is gone.

   ONE ENDPOINT IS LEFT, AND VK IS ITS ONLY CALLER:

     POST /vk/callback   ← VK asks it what an item costs (`get_item`) and tells it
                           when an order changed status (`order_status_change`).

   `get_item` is why this still has to run: VK builds the payment dialog from the
   price THIS FILE answers with, so an app with no reachable callback cannot sell
   anything at all. `order_status_change` is now bookkeeping — a durable record of
   what was actually charged, useful for support and reconciliation, but nothing the
   game waits on before handing over the item.

   ---- RUNNING IT ----
     VK_APP_ID=51234567 VK_APP_SECRET=xxx node server/vk-payments.js
   Zero dependencies, plain node:http, so it drops into whatever you already run.
   The store is a JSON file: fine for a first deploy, swap `store` for your database
   before this handles real volume — see the note on it.
   ============================================================================= */
'use strict';

const http   = require('http');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

/* ── CONFIG ────────────────────────────────────────────────────────────────────
   Both values come from the app's admin panel (Настройки → приложение):
     VK_APP_ID      — «ID приложения»
     VK_APP_SECRET  — «Защищённый ключ» → the key VK signs its payment callbacks
                      with (MD5 `sig`). OPTIONAL: leave it unset and the callback
                      answers unsigned notifications too, which keeps a
                      misconfigured key from breaking the storefront. Set it in
                      production — it costs nothing and keeps the ledger honest.
   🚨 The service access key is an API token, not this secret. */
const CFG = {
  appId:     process.env.VK_APP_ID     || '',
  appSecret: process.env.VK_APP_SECRET || '',
  port:      Number(process.env.PORT || 8080),
  storeFile: process.env.VK_STORE || path.join(__dirname, 'orders.json'),
  /* Set false once the app is live. VK sends `*_test` notification types while the
     app is in test mode, and keeping them out of the production ledger keeps test
     votes from looking like revenue. */
  allowTest: process.env.VK_ALLOW_TEST !== '0'
};

/* ── THE CATALOGUE ─────────────────────────────────────────────────────────────
   🚨 THIS MUST STAY IN SYNC WITH `vkProducts` IN index.html. VK asks THIS FILE for
   the price and title of an item (the `get_item` notification), and shows the
   player whatever it answers — so the price the player is charged comes from here,
   not from the admin panel and not from the client's display string.
   `price` is in ГОЛОСА (votes), integer, minimum 1. */
const CATALOGUE = {
  ants_lives_refill: {
    title: 'Полный запас жизней',
    price: 1,
    photo: ''            // optional absolute https URL shown in the payment dialog
  },
  ants_lives_unlimited_24h: {
    title: 'Безлимитные жизни на 24 часа',
    price: 5,
    photo: ''
  },
  ants_no_ads: {
    title: 'Без рекламы навсегда',
    price: 20,
    photo: ''
  }
};

/* ── STORE ─────────────────────────────────────────────────────────────────────
   A JSON file, read on boot and written on change. It holds two things:
     orders[order_id]      — every order already processed, for IDEMPOTENCY
     users[user_id][item]  — what each user owns
   🚨 IDEMPOTENCY IS NOT OPTIONAL. VK RETRIES a notification until it gets a valid
   response, and a network hiccup on our side after the grant means the same
   `order_status_change` arrives again. Without the orders table the player gets the
   item twice — which for a consumable is free goods, and for a subscription-shaped
   grant like the 24-hour window is a doubled duration on every retry.
   The callback is acknowledged only after an atomic file replacement succeeds. A
   successful VK response before durable storage is a paid order that can disappear
   forever if the process exits in the next millisecond.

   Swap this object for a transactional database before running multiple instances. */
const store = (() => {
  let data = { orders: {}, users: {} };
  try {
    data = JSON.parse(fs.readFileSync(CFG.storeFile, 'utf8'));
    data.orders = data.orders || {};
    data.users  = data.users  || {};
  } catch (e) { /* first run — the file does not exist yet */ }

  function flush() {
    const body = JSON.stringify(data, null, 1);
    const tmp = CFG.storeFile + '.' + process.pid + '.tmp';
    fs.mkdirSync(path.dirname(CFG.storeFile), { recursive: true });
    fs.writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o600 });
    try { fs.renameSync(tmp, CFG.storeFile); }
    catch (e) { try { fs.unlinkSync(tmp); } catch (_) {} throw e; }
  }

  return {
    seenOrder(orderId) { return Object.prototype.hasOwnProperty.call(data.orders, String(orderId)); },
    getOrder(orderId) { return data.orders[String(orderId)] || null; },
    recordOrder(orderId, rec) {
      const id = String(orderId);
      if (this.seenOrder(id)) return false;
      const uid = String(rec.user_id), item = String(rec.item);
      const hadUser = Object.prototype.hasOwnProperty.call(data.users, uid);
      const u = data.users[uid] || (data.users[uid] = {});
      const oldCount = Number(u[item] || 0);
      data.orders[id] = { ...rec, status: rec.status || 'confirmed' };
      u[item] = oldCount + 1;
      try { flush(); }
      catch (e) {
        delete data.orders[id];
        if (oldCount) u[item] = oldCount; else delete u[item];
        if (!hadUser && !Object.keys(u).length) delete data.users[uid];
        throw e;
      }
      return true;
    },
    refundOrder(orderId) {
      const id = String(orderId), rec = data.orders[id];
      if (!rec) return false;
      if (rec.status === 'refunded') return true;
      const uid = String(rec.user_id), item = String(rec.item);
      const u = data.users[uid] || (data.users[uid] = {});
      const oldCount = Number(u[item] || 0);
      const oldStatus = rec.status, oldAt = rec.refunded_at;
      rec.status = 'refunded'; rec.refunded_at = Date.now();
      u[item] = Math.max(0, oldCount - 1);
      try { flush(); }
      catch (e) {
        rec.status = oldStatus;
        if (oldAt == null) delete rec.refunded_at; else rec.refunded_at = oldAt;
        u[item] = oldCount;
        throw e;
      }
      return true;
    },
    countFor(userId, item) {
      const u = data.users[String(userId)];
      return Number(u && u[item]) || 0;
    }
  };
})();

/* ── THE CALLBACK SIGNATURE — `sig` ────────────────────────────────────────────
   MD5 over every request parameter EXCEPT `sig`, sorted by parameter name, joined
   as `key=value` with NO separator at all, with the app secret appended.
   Compared with timingSafeEqual rather than `===` — this is a secret-dependent
   comparison and a byte-by-byte early exit is measurable.

   This is VK signing ITS OWN notification to us; it is not the key check that was
   removed from the purchase flow, and the player never waits on it. It is skipped
   entirely when no secret is configured (see handleCallback), because a wrong or
   missing key must not be able to take the storefront down: without VK_APP_SECRET
   the worst a forged notification can do is write a bogus line into a ledger that
   grants nothing. */
function paymentSigOK(params) {
  const sig = String(params.sig || '');
  if (!sig || !CFG.appSecret) return false;   // callers check CFG.appSecret first
  const base = Object.keys(params)
    .filter(k => k !== 'sig')
    .sort()
    .map(k => k + '=' + params[k])
    .join('');
  const mine = crypto.createHash('md5').update(base + CFG.appSecret, 'utf8').digest('hex');
  return safeEqual(mine, sig.toLowerCase());
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a)), bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;          // length is not a secret
  return crypto.timingSafeEqual(ab, bb);
}

/* ── VK RESPONSE SHAPES ────────────────────────────────────────────────────────
   VK reads the BODY, not the HTTP status: a 200 carrying an `error` object is a
   failure, and a 500 is just a retry. Always answer 200 with one of these.
   `critical:false` tells VK the problem is transient and to retry; `true` tells it
   to give up and refund. Getting that backwards either strands the player's money
   or hammers this endpoint forever. */
function ok(res, response) { send(res, { response }); }
function err(res, code, msg, critical) {
  send(res, { error: { error_code: code, error_msg: msg, critical: !!critical } });
}
function send(res, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8',
                       'Content-Length': body.length });
  res.end(body);
}

/* ── THE CALLBACK ──────────────────────────────────────────────────────────────
   Two notification types matter for one-off items:

   get_item / get_item_test
     "A player is opening the payment dialog for `item`. What is it and what does
     it cost?" Answer with the catalogue entry. An unknown item must be error 20 —
     answering with a guess sells something that does not exist.

   order_status_change / order_status_change_test
     "The order reached `status`." The only status that means money moved is
     `chargeable`. Record the order id and echo back an app_order_id — VK retries
     until it gets one, and the record is what makes the retry harmless. The player
     already has the item: the page granted it the moment the dialog said success. */
function handleCallback(params, res) {
  if (CFG.appSecret && !paymentSigOK(params)) return err(res, 10, 'bad signature', true);
  if (CFG.appId && String(params.app_id) !== String(CFG.appId))
    return err(res, 10, 'wrong app_id', true);

  const type = String(params.notification_type || '');
  const isTest = /_test$/.test(type);
  if (isTest && !CFG.allowTest) return err(res, 10, 'test notifications are disabled', true);

  const base = type.replace(/_test$/, '');

  if (base === 'get_item') {
    const id   = String(params.item || '');
    const prod = CATALOGUE[id];
    /* 20 = "товар не существует". Critical, because retrying will not conjure it. */
    if (!prod) return err(res, 20, 'unknown item: ' + id, true);
    const out = { item_id: id, title: prod.title, price: prod.price };
    if (prod.photo) out.photo_url = prod.photo;
    return ok(res, out);
  }

  if (base === 'order_status_change') {
    const status  = String(params.status || '');
    const orderId = String(params.order_id || '');
    const userId  = String(params.user_id  || '');
    const item    = String(params.item     || '');
    if (!orderId || !userId) return err(res, 100, 'missing order/user id', true);

    if (status === 'refunded') {
      /* VK can refund an order after it was chargeable. The ledger records that;
         the game itself is not told, because it no longer asks this service
         anything — a refund is settled with the player, not with the client. */
      if (!store.getOrder(orderId)) return err(res, 100, 'original order not found', false);
      store.refundOrder(orderId);
      return ok(res, { order_id: Number(orderId), app_order_id: Number(orderId) });
    }

    if (status !== 'chargeable')
      return err(res, 100, 'unsupported status: ' + status, true);
    if (!CATALOGUE[item]) return err(res, 20, 'unknown item: ' + item, true);

    /* The retry path. Answering the SAME app_order_id for an order already
       processed is what makes a duplicate notification harmless — VK is satisfied
       and the player is not granted the item twice. */
    if (store.seenOrder(orderId)) {
      return ok(res, { order_id: Number(orderId), app_order_id: Number(orderId) });
    }

    store.recordOrder(orderId, {
      user_id: userId, item, at: Date.now(),
      price: params.item_price, test: isTest, status: 'confirmed'
    });
    console.log('[vk] charged %s to user %s (order %s%s)', item, userId, orderId, isTest ? ', TEST' : '');
    return ok(res, { order_id: Number(orderId), app_order_id: Number(orderId) });
  }

  return err(res, 100, 'unsupported notification_type: ' + type, true);
}

/* ── SERVER ────────────────────────────────────────────────────────────────────
   Bodies are capped: an unbounded read on a public endpoint is a way to be knocked
   over by one request. Nothing legitimate here is anywhere near 64KB. */
const MAX_BODY = 64 * 1024;

/* No CORS layer any more: the only client of this service is VK's own server, which
   sends no Origin header. The browser never talks to it. */
const server = http.createServer((req, res) => {
  const url = (req.url || '').split('?')[0];
  if (req.method !== 'POST') { res.writeHead(405); return res.end('POST only'); }

  let body = '', over = false;
  req.on('data', c => {
    if (over) return;
    body += c;
    if (body.length > MAX_BODY) { over = true; res.writeHead(413); res.end(); req.destroy(); }
  });
  req.on('end', () => {
    if (over) return;
    try {
      if (url === '/vk/callback') {
        const params = {};
        new URLSearchParams(body).forEach((v, k) => { params[k] = v; });
        return handleCallback(params, res);
      }
      res.writeHead(404); res.end('not found');
    } catch (e) {
      console.error('[vk] handler threw', e);
      /* critical:false — an exception here is our bug, not a bad order. Tell VK to
         retry rather than to refund a payment that probably succeeded. */
      err(res, 10, 'internal error', false);
    }
  });
});

if (require.main === module) {
  if (!CFG.appId) console.warn('[vk] WARNING: VK_APP_ID is not set — notifications from any app will be accepted');
  if (!CFG.appSecret) console.warn('[vk] WARNING: VK_APP_SECRET is not set — callback signatures are NOT checked');
  server.listen(CFG.port, () => console.log('[vk] payments callback listening on :' + CFG.port));
}

module.exports = { server, handleCallback, paymentSigOK, CATALOGUE, store, CFG };
