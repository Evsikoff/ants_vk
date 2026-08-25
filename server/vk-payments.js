/* =============================================================================
   VK PAYMENTS CALLBACK — server/vk-payments.js
   The half of the purchase flow that the client cannot do.

   ---- WHY THIS FILE EXISTS ----
   VKWebAppShowOrderBox resolves `{status:'success'|'cancel'|'fail'}` in the page.
   That is all it gives you: no order id, no amount, no signature, nothing a server
   could check. It reports how a DIALOG CLOSED, and a modified client can report
   whatever it likes. If the game grants an item on that string, the item is free to
   anyone who opens devtools.

   The real event is server-to-server: VK POSTs a signed `order_status_change`
   notification to the callback URL configured in the app's admin panel. That
   notification is the only trustworthy statement that money moved, and this file
   handles it.

   ---- THE TWO ENDPOINTS ----
     POST /vk/callback   ← VK calls this. Signed with `sig` (MD5). Grants the item.
     POST /vk/verify     ← the game calls this after the order box says 'success'.
                           Signed with the launch params' `sign` (HMAC-SHA256).
                           Answers "has this user actually paid for this item?"

   Two different signature schemes use the SAME protected app secret. Confusing the
   service access token for a signing secret is the most common failure here.

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
     VK_APP_SECRET  — «Защищённый ключ»  → signs BOTH payment callbacks (MD5
                      `sig`) and Mini Apps launch params (HMAC-SHA256 `sign`).
   🚨 The service access key is an API token, not the HMAC secret. Using it here
   makes every /vk/verify request fail after VK has already accepted the payment. */
const CFG = {
  appId:     process.env.VK_APP_ID     || '',
  appSecret: process.env.VK_APP_SECRET || '',
  port:      Number(process.env.PORT || 8080),
  storeFile: process.env.VK_STORE || path.join(__dirname, 'orders.json'),
  /* Empty = same-origin requests only. For a separately hosted frontend, list its
     exact origins (comma-separated); `*` is accepted for local/test deployments. */
  allowedOrigins: String(process.env.VK_ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean),
  /* Set false once the app is live. VK sends `*_test` notification types while the
     app is in test mode, and paying them out on production data is how test votes
     become real entitlements. */
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
    owns(userId, item) {
      const u = data.users[String(userId)];
      return !!(u && u[item]);
    },
    all(userId) { return data.users[String(userId)] || {}; },
    ordersFor(userId) {
      const uid = String(userId);
      return Object.keys(data.orders)
        .filter(id => String(data.orders[id].user_id) === uid)
        .map(id => {
          const r = data.orders[id];
          return {
            order_id: id,
            item: String(r.item),
            status: r.status || 'confirmed',
            at: Number(r.at) || 0,
            refunded_at: Number(r.refunded_at) || 0
          };
        })
        .sort((a, b) => a.at - b.at || String(a.order_id).localeCompare(String(b.order_id)));
    }
  };
})();

/* ── SIGNATURES ────────────────────────────────────────────────────────────────
   1) PAYMENT CALLBACK — `sig`
   MD5 over every request parameter EXCEPT `sig`, sorted by parameter name, joined
   as `key=value` with NO separator at all, with the app secret appended.
   Compared with timingSafeEqual rather than `===` — this is a secret-dependent
   comparison and a byte-by-byte early exit is measurable. */
function paymentSigOK(params) {
  const sig = String(params.sig || '');
  if (!sig || !CFG.appSecret) return false;
  const base = Object.keys(params)
    .filter(k => k !== 'sig')
    .sort()
    .map(k => k + '=' + params[k])
    .join('');
  const mine = crypto.createHash('md5').update(base + CFG.appSecret, 'utf8').digest('hex');
  return safeEqual(mine, sig.toLowerCase());
}

/* 2) LAUNCH PARAMS — `sign`
   HMAC-SHA256 over the `vk_*` parameters only, sorted by name, joined as a normal
   query string, keyed with the SECURE key, base64 made URL-safe.
   🚨 Only `vk_`-prefixed keys go in. Anything else the page happened to have in its
   URL is not part of what VK signed, and including it fails every check. */
function launchSignOK(params) {
  const sign = String(params.sign || '');
  if (!sign || !CFG.appSecret) return false;
  const qs = Object.keys(params)
    .filter(k => k.indexOf('vk_') === 0)
    .sort()
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
    .join('&');
  const mine = crypto.createHmac('sha256', CFG.appSecret)
    .update(qs)
    .digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return safeEqual(mine, sign);
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
     `chargeable`. Grant, record the order id, and echo back an app_order_id. */
function handleCallback(params, res) {
  if (!paymentSigOK(params)) return err(res, 10, 'bad signature', true);
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
      /* VK can refund an order after it was chargeable. Stop advertising it as an
         active entitlement; the client receives this status on its next sync. */
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
    console.log('[vk] granted %s to user %s (order %s%s)', item, userId, orderId, isTest ? ', TEST' : '');
    return ok(res, { order_id: Number(orderId), app_order_id: Number(orderId) });
  }

  return err(res, 100, 'unsupported notification_type: ' + type, true);
}

/* ── THE GAME'S VERIFY CALL ────────────────────────────────────────────────────
   The client posts {item, launch} after the order box reported success, and asks
   whether we have actually been paid. The launch params carry `sign`, which is the
   only thing here that proves WHO is asking — without checking it, anyone could
   post someone else's vk_user_id and be told they own the item.

   Note the race this is written around: the client can reach us BEFORE VK's
   server-to-server notification does. `granted:false` therefore means "not yet",
   not "never" — the client is expected to treat it as a failure for now and pick
   the entitlement up on the next launch, when the callback will long since have
   landed. */
function handleVerify(body, res) {
  let payload;
  try { payload = JSON.parse(body || '{}'); } catch (e) { payload = null; }
  if (!payload || typeof payload !== 'object') return send(res, { granted: false, reason: 'bad body' });

  const launch = payload.launch || {};
  const item   = String(payload.item || '');
  if (!launchSignOK(launch))   return send(res, { granted: false, reason: 'bad sign' });
  if (!CATALOGUE[item])        return send(res, { granted: false, reason: 'unknown item' });

  if (CFG.appId && String(launch.vk_app_id || '') !== String(CFG.appId))
    return send(res, { granted: false, reason: 'wrong app_id' });

  const userId = String(launch.vk_user_id || '');
  const orders = store.ordersFor(userId);
  const granted = orders.some(o => o.item === item && o.status === 'confirmed');
  return send(res, {
    granted,
    status: granted ? 'confirmed' : 'pending',
    orders,
    owns: store.all(userId),
    server_time: Date.now()
  });
}

/* ── SERVER ────────────────────────────────────────────────────────────────────
   Bodies are capped: an unbounded read on a public endpoint is a way to be knocked
   over by one request. Nothing legitimate here is anywhere near 64KB. */
const MAX_BODY = 64 * 1024;

function allowCors(req, res) {
  const origin = String(req.headers.origin || '');
  if (!origin) return true;                    // VK callback and non-browser clients
  const forwardedHost = String(req.headers['x-forwarded-host'] || req.headers.host || '')
    .split(',')[0].trim();
  let sameHost = false;
  try { sameHost = new URL(origin).host === forwardedHost; } catch (_) {}
  const allowed = sameHost || CFG.allowedOrigins.includes('*') || CFG.allowedOrigins.includes(origin);
  if (!allowed) return false;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
  return true;
}

const server = http.createServer((req, res) => {
  const url = (req.url || '').split('?')[0];
  const corsOK = allowCors(req, res);
  if (req.method === 'OPTIONS') {
    res.writeHead(corsOK ? 204 : 403); return res.end();
  }
  if (req.method !== 'POST') { res.writeHead(405); return res.end('POST only'); }
  if (url === '/vk/verify' && !corsOK) { res.writeHead(403); return res.end('origin not allowed'); }

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
      if (url === '/vk/verify') return handleVerify(body, res);
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
  for (const k of ['appId', 'appSecret']) {
    if (!CFG[k]) console.warn('[vk] WARNING: %s is not set — the matching signature check will reject everything', k);
  }
  server.listen(CFG.port, () => console.log('[vk] payments callback listening on :' + CFG.port));
}

module.exports = { server, handleCallback, handleVerify, paymentSigOK, launchSignOK, CATALOGUE, store, CFG };
