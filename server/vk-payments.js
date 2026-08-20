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

   Two different signature schemes with two different secrets, which is the single
   most common way this integration is got wrong — see the notes on each.

   ---- RUNNING IT ----
     VK_APP_ID=51234567 VK_APP_SECRET=xxx VK_SECURE_KEY=yyy node server/vk-payments.js
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
   All three come from the app's admin panel (Настройки → приложение):
     VK_APP_ID      — «ID приложения»
     VK_APP_SECRET  — «Защищённый ключ»  → signs the PAYMENT callbacks (MD5 `sig`)
     VK_SECURE_KEY  — «Сервисный ключ»   → signs the LAUNCH PARAMS (HMAC `sign`)
   🚨 These two keys are NOT interchangeable and the failure mode when they are
   swapped is silent: every signature simply fails to match, VK retries the
   notification for a while, and the player is charged with nothing granted. */
const CFG = {
  appId:     process.env.VK_APP_ID     || '',
  appSecret: process.env.VK_APP_SECRET || '',
  secureKey: process.env.VK_SECURE_KEY || '',
  port:      Number(process.env.PORT || 8080),
  storeFile: process.env.VK_STORE || path.join(__dirname, 'orders.json'),
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
   Swap this whole object for your database when there is one; the interface it
   needs is four methods and no transactions. */
const store = (() => {
  let data = { orders: {}, users: {} };
  try {
    data = JSON.parse(fs.readFileSync(CFG.storeFile, 'utf8'));
    data.orders = data.orders || {};
    data.users  = data.users  || {};
  } catch (e) { /* first run — the file does not exist yet */ }

  let writing = false, dirty = false;
  function flush() {
    if (writing) { dirty = true; return; }
    writing = true;
    const body = JSON.stringify(data, null, 1);
    fs.writeFile(CFG.storeFile + '.tmp', body, err => {
      if (!err) { try { fs.renameSync(CFG.storeFile + '.tmp', CFG.storeFile); } catch (e) {} }
      writing = false;
      if (dirty) { dirty = false; flush(); }
    });
  }

  return {
    seenOrder(orderId) { return Object.prototype.hasOwnProperty.call(data.orders, String(orderId)); },
    recordOrder(orderId, rec) { data.orders[String(orderId)] = rec; flush(); },
    grant(userId, item) {
      const u = data.users[String(userId)] || (data.users[String(userId)] = {});
      u[item] = (u[item] || 0) + 1;
      flush();
    },
    owns(userId, item) {
      const u = data.users[String(userId)];
      return !!(u && u[item]);
    },
    all(userId) { return data.users[String(userId)] || {}; }
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
  if (!sign || !CFG.secureKey) return false;
  const qs = Object.keys(params)
    .filter(k => k.indexOf('vk_') === 0)
    .sort()
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
    .join('&');
  const mine = crypto.createHmac('sha256', CFG.secureKey)
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
    if (String(params.status) !== 'chargeable')
      return err(res, 100, 'unsupported status: ' + params.status, true);

    const orderId = String(params.order_id || '');
    const userId  = String(params.user_id  || '');
    const item    = String(params.item     || '');
    if (!orderId || !userId || !CATALOGUE[item]) return err(res, 20, 'unknown item: ' + item, true);

    /* The retry path. Answering the SAME app_order_id for an order already
       processed is what makes a duplicate notification harmless — VK is satisfied
       and the player is not granted the item twice. */
    if (store.seenOrder(orderId)) {
      return ok(res, { order_id: Number(orderId), app_order_id: Number(orderId) });
    }

    store.grant(userId, item);
    store.recordOrder(orderId, {
      user_id: userId, item, at: Date.now(),
      price: params.item_price, test: isTest
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

  const userId = String(launch.vk_user_id || '');
  return send(res, {
    granted: store.owns(userId, item),
    owns: store.all(userId)
  });
}

/* ── SERVER ────────────────────────────────────────────────────────────────────
   Bodies are capped: an unbounded read on a public endpoint is a way to be knocked
   over by one request. Nothing legitimate here is anywhere near 64KB. */
const MAX_BODY = 64 * 1024;

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405); return res.end('POST only'); }

  let body = '', over = false;
  req.on('data', c => {
    if (over) return;
    body += c;
    if (body.length > MAX_BODY) { over = true; res.writeHead(413); res.end(); req.destroy(); }
  });
  req.on('end', () => {
    if (over) return;
    const url = (req.url || '').split('?')[0];
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
  for (const k of ['appId', 'appSecret', 'secureKey']) {
    if (!CFG[k]) console.warn('[vk] WARNING: %s is not set — the matching signature check will reject everything', k);
  }
  server.listen(CFG.port, () => console.log('[vk] payments callback listening on :' + CFG.port));
}

module.exports = { server, handleCallback, handleVerify, paymentSigOK, launchSignOK, CATALOGUE, store };
