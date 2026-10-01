// =====================================================================
// AI-прокси для российских нейросетей (Yandex Cloud Functions, Node.js 18+)
// GigaChat (Сбер) и YandexGPT. Нужен потому, что Cloudflare не доверяет
// сертификату Национального удостоверяющего центра Минцифры и обрывает
// соединение с серверами GigaChat (ошибка 526).
//
// Переменные окружения функции:
//   ACCESS_CODE    — тот же код доступа, что и в Cloudflare-прокси
//   GIGACHAT_AUTH  — «Ключ авторизации» GigaChat API (Base64)
//   FOLDER_ID      — идентификатор каталога Yandex Cloud (для YandexGPT)
// Необязательные: GIGACHAT_SCOPE, GIGACHAT_MODEL, YANDEX_MODEL (по умолчанию yandexgpt),
//   MINTSIFRY_CA_URL — адрес PEM-сертификата Минцифры, если стандартный адрес изменится;
//   MINTSIFRY_CA_PEM — сам текст сертификата (если автозагрузка с портала Госуслуг не работает).
// Для YandexGPT к функции привязывается сервисный аккаунт с ролью ai.languageModels.user:
// IAM-токен функция получает автоматически, отдельный API-ключ не нужен.
// =====================================================================
'use strict';
const https = require('https');
const crypto = require('crypto');

const MAX_TOKENS = 8000;
const MAX_CHARS = 150000;
const CA_URLS = [
  'https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt',
  'https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt'
];
let caPem = null, caError = '';
let gigaToken = null, gigaTokenExp = 0;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Access-Code',
  'Access-Control-Max-Age': '86400'
};
const reply = (statusCode, obj) => ({ statusCode, headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, CORS), body: JSON.stringify(obj) });

// HTTPS-запрос через модуль https: позволяет передать собственный корневой сертификат (ca).
function request(url, { method = 'GET', headers = {}, body = null, ca = null, timeout = 110000 } = {}) {
  return new Promise((resolve, reject) => {
    // Явная длина тела: сервер авторизации Сбера не принимает запросы без Content-Length
    // (chunked) и обрывает соединение через 60 с («socket hang up»).
    const h = Object.assign({ 'User-Agent': 'upzi-ai-proxy/1.0' }, headers);
    if (body !== null && body !== undefined) h['Content-Length'] = Buffer.byteLength(body);
    const opts = { method, headers: h, timeout, family: 4 };   // только IPv4
    if (ca) opts.ca = ca;
    const host = new URL(url).host, t0 = Date.now();
    console.log('→', method, host, new URL(url).pathname);
    const r = https.request(url, opts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => { console.log('←', res.statusCode, host, (Date.now() - t0) + ' мс'); resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }); });
    });
    r.on('socket', sock => sock.on('secureConnect', () => console.log('  TLS ok', host, (Date.now() - t0) + ' мс')));
    r.on('timeout', () => r.destroy(new Error('нет ответа за ' + Math.round(timeout / 1000) + ' с')));
    r.on('error', e => { console.error('✗', host, (Date.now() - t0) + ' мс', e.message); reject(new Error(e.message + ' [' + host + ']')); });
    if (body) r.write(body);
    r.end();
  });
}

function errText(name, res) {
  let msg = res.text;
  try { const j = JSON.parse(res.text); msg = (j.error && (j.error.message || j.error)) || j.message || res.text; } catch (e) {}
  return name + ': ' + String(msg || ('HTTP ' + res.status)).slice(0, 300);
}

// Сертификат Минцифры: стандартные корневые сертификаты + загруженные с портала Госуслуг.
async function loadCa() {
  if (caPem) return caPem;
  // Запасной путь: текст сертификата вставлен прямо в переменную окружения MINTSIFRY_CA_PEM.
  if (process.env.MINTSIFRY_CA_PEM && process.env.MINTSIFRY_CA_PEM.includes('BEGIN CERTIFICATE')) {
    caPem = require('tls').rootCertificates.concat([process.env.MINTSIFRY_CA_PEM.replace(/\\n/g, '\n')]);
    return caPem;
  }
  const urls = process.env.MINTSIFRY_CA_URL ? [process.env.MINTSIFRY_CA_URL] : CA_URLS;
  const pems = [];
  for (const u of urls) {
    try {
      const r = await request(u, { timeout: 15000 });
      if (r.status === 200 && r.text.includes('BEGIN CERTIFICATE')) pems.push(r.text);
    } catch (e) { caError = 'сертификат Минцифры не загрузился: ' + e.message; }
  }
  if (!pems.length) throw new Error((caError || 'сертификат Минцифры не найден по адресу ' + urls[0]) + '. Вставьте текст сертификата в переменную MINTSIFRY_CA_PEM');
  caPem = require('tls').rootCertificates.concat(pems);
  return caPem;
}

async function gigaAccessToken() {
  if (gigaToken && Date.now() < gigaTokenExp - 60000) return gigaToken;
  const ca = await loadCa();
  const r = await request('https://ngw.devices.sberbank.ru:9443/api/v2/oauth', {
    method: 'POST', ca,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', RqUID: crypto.randomUUID(), Authorization: 'Basic ' + process.env.GIGACHAT_AUTH },
    body: 'scope=' + encodeURIComponent(process.env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS')
  });
  if (r.status !== 200) throw new Error(errText('GigaChat (авторизация)', r));
  const j = JSON.parse(r.text);
  gigaToken = j.access_token;
  gigaTokenExp = j.expires_at || (Date.now() + 25 * 60 * 1000);
  return gigaToken;
}

async function callGigaChat(o) {
  const token = await gigaAccessToken();
  const msgs = (o.system ? [{ role: 'system', content: o.system }] : []).concat(o.messages);
  const r = await request('https://gigachat.devices.sberbank.ru/api/v1/chat/completions', {
    method: 'POST', ca: await loadCa(),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: 'Bearer ' + token },
    body: JSON.stringify({ model: process.env.GIGACHAT_MODEL || 'GigaChat', temperature: o.json ? 0.2 : 0.5, max_tokens: o.maxTokens, messages: msgs })
  });
  if (r.status !== 200) throw new Error(errText('GigaChat', r));
  const j = JSON.parse(r.text);
  return { text: (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '', model: j.model || process.env.GIGACHAT_MODEL || 'GigaChat' };
}

async function callYandexGPT(o, iamToken) {
  if (!iamToken) throw new Error('YandexGPT: к функции не привязан сервисный аккаунт (нужна роль ai.languageModels.user)');
  const model = process.env.YANDEX_MODEL || 'yandexgpt';
  const msgs = (o.system ? [{ role: 'system', text: o.system }] : []).concat(o.messages.map(m => ({ role: m.role, text: m.content })));
  const r = await request('https://llm.api.cloud.yandex.net/foundationModels/v1/completion', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + iamToken, 'x-folder-id': process.env.FOLDER_ID },
    body: JSON.stringify({
      modelUri: 'gpt://' + process.env.FOLDER_ID + '/' + model + '/latest',
      completionOptions: { stream: false, temperature: o.json ? 0.2 : 0.5, maxTokens: String(Math.min(o.maxTokens, 8000)) },
      messages: msgs
    })
  });
  if (r.status !== 200) throw new Error(errText('YandexGPT', r));
  const j = JSON.parse(r.text);
  const alt = j.result && j.result.alternatives && j.result.alternatives[0];
  return { text: (alt && alt.message && alt.message.text) || '', model: model + (j.result && j.result.modelVersion ? ' (' + j.result.modelVersion + ')' : '') };
}

module.exports.handler = async function (event, context) {
  const method = (event.httpMethod || 'GET').toUpperCase();
  if (method === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  const headers = {};
  Object.keys(event.headers || {}).forEach(k => { headers[k.toLowerCase()] = event.headers[k]; });
  const codeOk = !process.env.ACCESS_CODE || headers['x-access-code'] === process.env.ACCESS_CODE;
  const iamToken = context && context.token && context.token.access_token;

  if (method === 'GET') {
    return reply(200, {
      ok: true, accessCodeRequired: !!process.env.ACCESS_CODE, accessCodeOk: codeOk,
      providers: {
        gigachat: { configured: !!process.env.GIGACHAT_AUTH, model: process.env.GIGACHAT_MODEL || 'GigaChat' },
        yandexgpt: { configured: !!(process.env.FOLDER_ID && iamToken), model: process.env.YANDEX_MODEL || 'yandexgpt' }
      }
    });
  }
  if (method !== 'POST') return reply(405, { error: 'используйте GET (статус) или POST (запрос)' });
  if (!codeOk) return reply(401, { error: 'неверный или отсутствующий код доступа' });

  let body;
  try { body = JSON.parse(event.isBase64Encoded ? Buffer.from(event.body || '', 'base64').toString('utf8') : (event.body || '{}')); }
  catch (e) { return reply(400, { error: 'тело запроса — не JSON' }); }
  const provider = String(body.provider || '');
  const messages = Array.isArray(body.messages)
    ? body.messages.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim()).map(m => ({ role: m.role, content: m.content }))
    : [{ role: 'user', content: String(body.prompt || '') }];
  const o = {
    system: String(body.system || '').slice(0, 8000), messages,
    maxTokens: Math.min(MAX_TOKENS, Math.max(64, parseInt(body.maxTokens || 2000, 10) || 2000)),
    json: body.json !== false
  };
  if (!messages.length || !messages[messages.length - 1].content.trim() || messages[messages.length - 1].role !== 'user') return reply(400, { error: 'пустой запрос' });
  if (messages.reduce((n, m) => n + m.content.length, 0) > MAX_CHARS) return reply(400, { error: 'диалог слишком длинный — начните новый' });

  try {
    if (provider === 'gigachat') {
      if (!process.env.GIGACHAT_AUTH) return reply(400, { error: 'ключ GigaChat не добавлен в функцию' });
      return reply(200, await callGigaChat(o));
    }
    if (provider === 'yandexgpt') {
      if (!process.env.FOLDER_ID) return reply(400, { error: 'не задан FOLDER_ID' });
      return reply(200, await callYandexGPT(o, iamToken));
    }
    return reply(400, { error: 'эта функция обслуживает только gigachat и yandexgpt' });
  } catch (e) {
    console.error('proxy error', provider, e && e.stack || e);
    return reply(502, { error: String(e && e.message || e) });
  }
};
