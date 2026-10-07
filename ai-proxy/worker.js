// =====================================================================
// AI-прокси практикума УПЗИиЭЗИ (Cloudflare Worker)
// Хранит API-ключи нейросетей в «секретах» Cloudflare, чтобы они не попадали
// в index.html, опубликованный на GitHub Pages. Страница практикума шлёт сюда
// текст задания, прокси добавляет ключ и пересылает запрос нужной нейросети.
//
// Секреты (Settings → Variables and Secrets → Type: Secret), все необязательны —
// какие заданы, те нейросети и доступны:
//   CLAUDE_KEY      — ключ Anthropic (console.anthropic.com)
//   QWEN_KEY        — ключ Alibaba DashScope (международный)
//   DEEPSEEK_KEY    — ключ DeepSeek (platform.deepseek.com)
//   GEMINI_KEY      — ключ Google AI Studio
//   GIGACHAT_AUTH   — «Ключ авторизации» GigaChat API (Base64-строка из кабинета Сбера)
//   OPENROUTER_KEY  — ключ openrouter.ai: даёт до 3 дополнительных моделей (or1..or3); без карты
//                     доступны бесплатные модели (:free), прокси сам выбирает их от разных разработчиков
//   ACCESS_CODE     — код доступа для студентов (если задан, без него прокси не отвечает)
// Переменные (Type: Text), тоже необязательны:
//   ALLOWED_ORIGINS — через запятую; по умолчанию сайт практикума + локальный файл (null)
//   CLAUDE_MODEL, QWEN_MODEL, DEEPSEEK_MODEL, GEMINI_MODEL, GIGACHAT_MODEL, GIGACHAT_SCOPE
//   OPENROUTER_MODELS — свой список моделей OpenRouter через запятую (вместо автоподбора)
//   PERPLEXITY_MODEL, GEMINI_WEB_MODEL — модели поисковых каналов (по умолчанию perplexity/sonar-pro и новейшая google/gemini-*-flash)
// Поисковые каналы для «Поиска в 4 канала» (perplexity, gemini_web) идут через OPENROUTER_KEY.
//   RATE_LIMIT      — запросов с одного IP за 10 минут (по умолчанию 300 — в классе все компьютеры часто выходят через один IP)
// =====================================================================

const DEFAULT_ORIGINS = 'https://goxaman2-dot.github.io,null';
const MAX_PROMPT_CHARS = 150000;
const MAX_TOKENS = 8000;
const WINDOW_MS = 10 * 60 * 1000;

const PROVIDERS = {
  claude:   { label: 'Claude', key: 'CLAUDE_KEY',    model: env => env.CLAUDE_MODEL   || 'claude-haiku-4-5-20251001' },
  qwen:     { label: 'Qwen', key: 'QWEN_KEY',      model: env => env.QWEN_MODEL     || 'qwen-plus' },
  deepseek: { label: 'DeepSeek', key: 'DEEPSEEK_KEY',  model: env => env.DEEPSEEK_MODEL || 'deepseek-chat' },
  gemini:   { label: 'Gemini', key: 'GEMINI_KEY',    model: env => env.GEMINI_MODEL   || 'gemini-2.5-flash' },
  gigachat: { label: 'GigaChat', key: 'GIGACHAT_AUTH', model: env => env.GIGACHAT_MODEL || 'GigaChat' },
  // GLM (Z.ai): бесплатная модель OpenRouter по тому же OPENROUTER_KEY; GLM_MODEL — свой id модели.
  glm:      { label: 'GLM', key: 'OPENROUTER_KEY', model: env => env.GLM_MODEL || 'z-ai/glm-5.2:free' }
};

// Счётчик запросов живёт в памяти одного экземпляра воркера — это защита «от дурака»
// (случайный цикл, скрипт студента), а не строгий лимит: экземпляров может быть несколько.
const hits = new Map();
let gigaToken = null, gigaTokenExp = 0;

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map(s => s.trim());
  const ok = allowed.includes(origin) || allowed.includes('*');
  return {
    'Access-Control-Allow-Origin': ok ? (origin || '*') : allowed[0],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Access-Code',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function json(body, status, req, env) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(req, env) }
  });
}

function originAllowed(req, env) {
  const origin = req.headers.get('Origin');
  if (origin === null) return true; // запрос не из браузера (curl) — CORS не применяется
  const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map(s => s.trim());
  return allowed.includes(origin) || allowed.includes('*');
}

function rateLimited(req, env) {
  const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
  const limit = parseInt(env.RATE_LIMIT || '300', 10);
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(t => now - t < WINDOW_MS);
  if (list.length >= limit) { hits.set(ip, list); return true; }
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return false;
}

async function readError(r, name) {
  const t = await r.text().catch(() => '');
  let msg = t;
  try {
    const j = JSON.parse(t); msg = (j.error && (j.error.message || j.error)) || j.message || t;
    const md = j.error && j.error.metadata;   // OpenRouter: имя провайдера и его исходная ошибка
    if (md && (md.provider_name || md.raw)) msg += ' [' + [md.provider_name, typeof md.raw === 'string' ? md.raw : JSON.stringify(md.raw || '')].filter(Boolean).join(': ').slice(0, 200) + ']';
  } catch (e) {}
  return name + ': ' + String(msg || ('HTTP ' + r.status)).slice(0, 300);
}

// o = { system, messages:[{role:'user'|'assistant', content}], maxTokens, json, search }
// json:true — ответ строго JSON (режим практикума); search:true — веб-поиск, где модель его поддерживает.
async function callClaude(env, o) {
  const body = { model: PROVIDERS.claude.model(env), max_tokens: o.maxTokens, temperature: o.json ? 0.2 : 0.5, system: o.system, messages: o.messages };
  if (o.search) body.tools = [{ type: 'web_search_20250305', name: 'web_search', max_uses: 5 }];
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': env.CLAUDE_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await readError(r, 'Claude'));
  const j = await r.json();
  return (j.content || []).filter(x => x.type === 'text').map(x => x.text).join('');
}

async function callOpenAICompatible(url, key, model, o, name, extra, extraHeaders) {
  const msgs = (o.system ? [{ role: 'system', content: o.system }] : []).concat(o.messages);
  // Таймер охватывает и чтение тела: OpenRouter шлёт заголовки сразу, а ответ может «висеть» минутами.
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 150000);
  let r, j;
  try {
    r = await fetch(url, {
      method: 'POST', signal: ctl.signal,
      headers: Object.assign({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + String(key).trim() }, extraHeaders || {}),
      body: JSON.stringify(Object.assign({ model, temperature: o.json ? 0.2 : 0.5, max_tokens: o.maxTokens, messages: msgs }, extra || {}))
    });
    if (!r.ok) throw new Error(await readError(r, name));
    j = await r.json();
  } catch (e) {
    if (e && e.name === 'AbortError') throw new Error(name + ': нет ответа 150 секунд — сервер модели перегружен. Нажмите «Повторить» позже или выключите эту модель.');
    throw e && e.message && e.message.startsWith(name) ? e : new Error(name + ': ' + String(e && e.message || e));
  } finally { clearTimeout(timer); }
  const ch = (j.choices && j.choices[0]) || {}, msg = ch.message || {};
  let text = Array.isArray(msg.content) ? msg.content.map(x => (x && (x.text || x.content)) || '').join('') : (msg.content || '');
  if (!text.trim()) {
    // Рассуждающие модели (DeepSeek, Qwen и др.) иногда тратят весь лимит на «мысли» и не успевают дать ответ.
    const thought = msg.reasoning_content || msg.reasoning || '';
    if (ch.finish_reason === 'length') throw new Error(name + ': модель израсходовала лимит длины на рассуждения и не дала ответа. Сократите документ или задайте вопрос по одному разделу.');
    if (thought) return '_Модель вернула только ход рассуждений:_\n\n' + thought;
    throw new Error(name + ': пустой ответ (finish_reason: ' + (ch.finish_reason || 'нет') + '). Нажмите «Повторить».');
  }
  return text;
}

async function callGemini(env, o) {
  const model = PROVIDERS.gemini.model(env);
  const body = {
    systemInstruction: { parts: [{ text: o.system || ' ' }] },
    contents: o.messages.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
    generationConfig: { temperature: o.json ? 0.2 : 0.5, maxOutputTokens: o.maxTokens }
  };
  if (o.search) body.tools = [{ google_search: {} }];       // поиск Google несовместим с JSON-режимом
  else if (o.json) body.generationConfig.responseMimeType = 'application/json';
  const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_KEY },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await readError(r, 'Gemini'));
  const j = await r.json();
  const parts = (j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || [];
  return parts.map(p => p.text || '').join('');
}

async function gigaAccessToken(env) {
  if (gigaToken && Date.now() < gigaTokenExp - 60000) return gigaToken;
  const r = await fetch('https://ngw.devices.sberbank.ru:9443/api/v2/oauth', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      RqUID: crypto.randomUUID(),
      Authorization: 'Basic ' + env.GIGACHAT_AUTH
    },
    body: 'scope=' + encodeURIComponent(env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS')
  });
  if (!r.ok) throw new Error(await readError(r, 'GigaChat (авторизация)'));
  const j = await r.json();
  gigaToken = j.access_token;
  gigaTokenExp = j.expires_at || (Date.now() + 25 * 60 * 1000);
  return gigaToken;
}

async function callGigaChat(env, o) {
  const token = await gigaAccessToken(env);
  return callOpenAICompatible('https://gigachat.devices.sberbank.ru/api/v1/chat/completions', token, PROVIDERS.gigachat.model(env), o, 'GigaChat');
}

// ---------- OpenRouter: до трёх моделей по одному ключу ----------
// Предпочтение разработчикам по порядку; из каждого берётся одна бесплатная (:free) модель.
const OR_VENDORS = ['deepseek', 'qwen', 'meta-llama', 'google', 'mistralai', 'moonshotai', 'z-ai', 'nvidia', 'microsoft', 'openai'];
let orCache = null, orCacheAt = 0, orFreeAll = [];
async function openRouterModels(env) {
  if (!env.OPENROUTER_KEY) return [];
  if (env.OPENROUTER_MODELS) return env.OPENROUTER_MODELS.split(',').map(x => x.trim()).filter(Boolean).slice(0, 3);
  if (orCache && Date.now() - orCacheAt < 3600000) return orCache;
  try {
    const r = await fetch('https://openrouter.ai/api/v1/models');
    const j = await r.json();
    const free = (j.data || []).filter(m => /:free$/.test(m.id) && (!m.architecture || !m.architecture.output_modalities || m.architecture.output_modalities.includes('text')));
    const picked = [];
    for (const v of OR_VENDORS) {
      const cands = free.filter(m => m.id.startsWith(v + '/')).sort((a, b) => (b.created || 0) - (a.created || 0));
      if (cands.length) picked.push(cands[0].id);
      if (picked.length === 3) break;
    }
    for (const m of free) { if (picked.length >= 3) break; if (!picked.includes(m.id) && !picked.some(p => p.split('/')[0] === m.id.split('/')[0])) picked.push(m.id); }
    orCache = picked; orCacheAt = Date.now();
    orFreeAll = free.sort((a, b) => (b.created || 0) - (a.created || 0)).map(m => m.id);
    return picked;
  } catch (e) { return orCache || []; }
}
const orName = id => { const n = id.split('/').pop().replace(/:free$/, ''); return n.length > 22 ? n.slice(0, 22) + '…' : n; };

// ---------- Платные модели через тот же ключ OpenRouter ----------
// VIA_OPENROUTER = "claude,deepseek,qwen,gemini" — эти нейросети идут через OpenRouter
// (оплата с баланса OpenRouter, отдельные ключи и карты не нужны). Модель берётся из
// CLAUDE_MODEL и т. п., если там указан id OpenRouter (с «/»), иначе выбирается самая новая.
const OR_PAID = {
  claude:   /^anthropic\/claude-sonnet-[\d.-]+$/,
  deepseek: /^deepseek\/deepseek-(chat|v)[\w.-]*$/,
  qwen:     /^qwen\/qwen[\d.]*-(plus|max)[\w.-]*$/,
  gemini:   /^google\/gemini-[\d.]+-flash$/
};
const viaOR = (id, env) => !!env.OPENROUTER_KEY && !!OR_PAID[id] &&
  String(env.VIA_OPENROUTER || '').split(',').map(x => x.trim().toLowerCase()).includes(id);
let orAll = null, orAllAt = 0;
async function orCatalog() {
  if (orAll && Date.now() - orAllAt < 3600000) return orAll;
  const r = await fetch('https://openrouter.ai/api/v1/models');
  orAll = ((await r.json()).data || []); orAllAt = Date.now();
  return orAll;
}
async function orPaidModel(id, env) {
  const own = env[id.toUpperCase() + '_MODEL'];
  if (own && own.includes('/')) return own;
  try {
    const c = (await orCatalog()).filter(m => OR_PAID[id].test(m.id)).sort((a, b) => (b.created || 0) - (a.created || 0));
    if (c.length) return c[0].id;
  } catch (e) {}
  return { claude: 'anthropic/claude-sonnet-4.5', deepseek: 'deepseek/deepseek-chat', qwen: 'qwen/qwen-plus', gemini: 'google/gemini-2.5-flash' }[id];
}
// ---------- ProxyAPI (proxyapi.ru): оплата в рублях российской картой ----------
// PROXYAPI_KEY + VIA_PROXYAPI = "deepseek,claude,gemini,qwen". Имеет приоритет над OpenRouter.
// Модель: DEEPSEEK_MODEL и т. п. в формате «вендор/модель» или значение по умолчанию ниже.
const PX_DEFAULT = { deepseek: 'deepseek/deepseek-v4.1-flash', claude: 'anthropic/claude-sonnet-5-5', gemini: 'google/gemini-2.5-flash', qwen: 'qwen/qwen-plus' };
const viaPX = (id, env) => !!env.PROXYAPI_KEY && !!PX_DEFAULT[id] &&
  String(env.VIA_PROXYAPI || '').split(',').map(x => x.trim().toLowerCase()).includes(id);
const pxModel = (id, env) => { const own = env[id.toUpperCase() + '_MODEL']; return own && own.includes('/') ? own : PX_DEFAULT[id]; };
const gatewayOf = (id, env) => env[PROVIDERS[id].key] ? '' : viaPX(id, env) ? 'ProxyAPI' : viaOR(id, env) ? 'OpenRouter' : '';

const OR_HEADERS = { 'HTTP-Referer': 'https://goxaman2-dot.github.io/upzi-praktikum/', 'X-Title': 'UPZI synthetic panel' };
const isConfigured = (id, env) => id === 'glm' ? !!env.OPENROUTER_KEY : (!!env[PROVIDERS[id].key] || !!gatewayOf(id, env));
const modelOf = async (id, env) => { if (id === 'glm') return (await glmModels(env))[0]; const g = gatewayOf(id, env); return g === 'ProxyAPI' ? pxModel(id, env) : g === 'OpenRouter' ? orPaidModel(id, env) : PROVIDERS[id].model(env); };

// ---------- GLM (Z.ai) через OpenRouter, бесплатно ----------
// Основная модель — GLM_MODEL или самая новая бесплатная z-ai/…:free из каталога OpenRouter;
// остальные бесплатные GLM идут запасными: если основная перегружена, OpenRouter переключится сам.
let glmCache = null, glmCacheAt = 0;
async function glmModels(env) {
  const fallback = ['z-ai/glm-5.2:free', 'z-ai/glm-4.5-air:free'];
  if (glmCache && Date.now() - glmCacheAt < 3600000) return glmCache;
  let free = [];
  try {
    const r = await fetch('https://openrouter.ai/api/v1/models');
    const j = await r.json();
    free = (j.data || []).filter(m => /^z-ai\/.*:free$/.test(m.id)).sort((a, b) => (b.created || 0) - (a.created || 0)).map(m => m.id);
  } catch (e) { /* каталог недоступен — берём значения по умолчанию */ }
  const main = env.GLM_MODEL || free[0] || fallback[0];
  const list = [main].concat(free.length ? free : fallback).filter((x, i, a) => a.indexOf(x) === i).slice(0, 3);
  glmCache = list; glmCacheAt = Date.now();
  return list;
}

async function dispatch(provider, env, o) {
  if (provider === 'glm') {
    const list = await glmModels(env);
    return callOpenAICompatible('https://openrouter.ai/api/v1/chat/completions', env.OPENROUTER_KEY, list[0], o, 'GLM (' + orName(list[0]) + ')',
      list.length > 1 ? { models: list } : {}, OR_HEADERS);
  }
  const jsonMode = o.json ? { response_format: { type: 'json_object' } } : {};
  if (PROVIDERS[provider] && gatewayOf(provider, env) === 'ProxyAPI') {
    return callOpenAICompatible('https://api.proxyapi.ru/v1/chat/completions', env.PROXYAPI_KEY, pxModel(provider, env), o,
      PROVIDERS[provider].label + ' via ProxyAPI', jsonMode);
  }
  if (PROVIDERS[provider] && !env[PROVIDERS[provider].key] && viaOR(provider, env)) {
    const model = await orPaidModel(provider, env);
    const extra = Object.assign({}, jsonMode, o.search ? { plugins: [{ id: 'web', max_results: 5 }] } : {});
    return callOpenAICompatible('https://openrouter.ai/api/v1/chat/completions', env.OPENROUTER_KEY, model, o,
      PROVIDERS[provider].label + ' via OpenRouter', extra, OR_HEADERS);
  }
  switch (provider) {
    case 'claude':   return callClaude(env, o);
    case 'qwen':     return callOpenAICompatible('https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions', env.QWEN_KEY, PROVIDERS.qwen.model(env), o, 'Qwen',
                       o.search ? { enable_search: true } : jsonMode);
    case 'deepseek': return callOpenAICompatible('https://api.deepseek.com/chat/completions', env.DEEPSEEK_KEY, PROVIDERS.deepseek.model(env), o, 'DeepSeek', jsonMode);
    case 'gemini':   return callGemini(env, o);
    case 'gigachat': return callGigaChat(env, o);
  }
  const m = /^or([123])$/.exec(provider);
  if (m) {
    const models = await openRouterModels(env);
    const model = models[+m[1] - 1];
    if (!model) throw new Error('OpenRouter: модель №' + m[1] + ' не выбрана');
    // Запасные бесплатные модели: если провайдер основной модели перегружен, OpenRouter сам переключится.
    const spare = orFreeAll.filter(x => !models.includes(x)).slice((+m[1] - 1) * 2, (+m[1] - 1) * 2 + 2);
    return callOpenAICompatible('https://openrouter.ai/api/v1/chat/completions', env.OPENROUTER_KEY, model, o, 'OpenRouter (' + orName(model) + ')',
      spare.length ? { models: [model].concat(spare) } : {}, OR_HEADERS);
  }
  throw new Error('неизвестная нейросеть: ' + provider);
}

// ---------- Поисковые каналы через OpenRouter (Perplexity, Gemini с веб-поиском) ----------
const SEARCH = { perplexity: 'Perplexity', gemini_web: 'Gemini + веб' };
async function searchModel(id, env) {
  if (id === 'perplexity') return env.PERPLEXITY_MODEL || 'perplexity/sonar-pro';
  if (env.GEMINI_WEB_MODEL) return env.GEMINI_WEB_MODEL.replace(/:online$/, '');
  try {
    const c = (await orCatalog()).filter(m => OR_PAID.gemini.test(m.id)).sort((a, b) => (b.created || 0) - (a.created || 0));
    if (c.length) return c[0].id;
  } catch (e) {}
  return 'google/gemini-2.5-flash';
}
// Источники: поля Perplexity (search_results, citations) и аннотации url_citation OpenRouter.
function sourcesOf(j) {
  const m = (j.choices && j.choices[0] && j.choices[0].message) || {};
  if (Array.isArray(j.search_results) && j.search_results.length) return j.search_results.map(s => ({ url: s.url, title: s.title || '', date: s.date || '' }));
  if (Array.isArray(j.citations) && j.citations.length) return j.citations.map(c => typeof c === 'string' ? { url: c, title: '' } : { url: c.url, title: c.title || '' });
  return (m.annotations || []).filter(a => a && a.url_citation).map(a => ({ url: a.url_citation.url, title: a.url_citation.title || '' }));
}
async function orSend(env, payload, name) {
  const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 150000);
  try {
    const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST', signal: ctl.signal,
      headers: Object.assign({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + String(env.OPENROUTER_KEY).trim() }, OR_HEADERS),
      body: JSON.stringify(payload)
    });
    if (!r.ok) return { ok: false, err: await readError(r, name) };
    return { ok: true, j: await r.json() };
  } catch (e) {
    return { ok: false, err: name + ': ' + (e && e.name === 'AbortError' ? 'нет ответа 150 секунд' : String(e && e.message || e)) };
  } finally { clearTimeout(timer); }
}
async function callSearch(id, env, o) {
  const name = SEARCH[id] + ' via OpenRouter';
  const model = await searchModel(id, env);
  const messages = (o.system ? [{ role: 'system', content: o.system }] : []).concat(o.messages);
  // Perplexity ищет сам; Gemini — сначала модель с суффиксом :online, затем плагин web, затем без поиска.
  const tries = id === 'perplexity' ? [{ model }]
    : [{ model: model + ':online' }, { model, plugins: [{ id: 'web', max_results: 8 }] }, { model, noSearch: true }];
  let lastErr = '';
  for (const t of tries) {
    const p = { model: t.model, max_tokens: o.maxTokens, temperature: 0.3, messages };
    if (t.plugins) p.plugins = t.plugins;
    const res = await orSend(env, p, name);
    if (!res.ok) { lastErr = res.err; continue; }
    const j = res.j, msg = (j.choices && j.choices[0] && j.choices[0].message) || {};
    const text = Array.isArray(msg.content) ? msg.content.map(x => (x && x.text) || '').join('') : (msg.content || '');
    if (!text.trim()) { lastErr = name + ': пустой ответ'; continue; }
    return { text, sources: sourcesOf(j).filter(s => s && s.url), model: (j.model || t.model) + (t.noSearch ? ' · веб-поиск недоступен, ответ по памяти' : '') };
  }
  throw new Error(lastErr || name + ': нет ответа');
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req, env) });
    if (!originAllowed(req, env)) return json({ error: 'запрос с этого сайта не разрешён (ALLOWED_ORIGINS)' }, 403, req, env);

    const url = new URL(req.url);
    const codeOk = !env.ACCESS_CODE || req.headers.get('X-Access-Code') === env.ACCESS_CODE;

    if (req.method === 'GET' && url.pathname.replace(/\/+$/, '') === '/status') {
      const providers = {};
      for (const id of Object.keys(PROVIDERS)) {
        providers[id] = { configured: isConfigured(id, env), model: await modelOf(id, env) };
        if (id === 'glm') providers[id].via = 'OpenRouter';
        else if (gatewayOf(id, env)) providers[id].via = gatewayOf(id, env);
      }
      (await openRouterModels(env)).forEach((mid, i) => { providers['or' + (i + 1)] = { configured: true, model: mid, name: orName(mid), via: 'OpenRouter' }; });
      for (const id of Object.keys(SEARCH)) providers[id] = { configured: !!env.OPENROUTER_KEY, model: env.OPENROUTER_KEY ? await searchModel(id, env) : '', via: 'OpenRouter' };
      return json({ ok: true, accessCodeRequired: !!env.ACCESS_CODE, accessCodeOk: codeOk, providers }, 200, req, env);
    }

    if (req.method !== 'POST') return json({ error: 'используйте POST /chat или GET /status' }, 405, req, env);
    if (!codeOk) return json({ error: 'неверный или отсутствующий код доступа — спросите его у преподавателя' }, 401, req, env);
    if (rateLimited(req, env)) return json({ error: 'слишком много запросов с этого компьютера, подождите 10 минут' }, 429, req, env);

    let body;
    try { body = await req.json(); } catch (e) { return json({ error: 'тело запроса — не JSON' }, 400, req, env); }
    const provider = String(body.provider || '');
    const system = String(body.system || '').slice(0, 8000);
    const maxTokens = Math.min(MAX_TOKENS, Math.max(64, parseInt(body.maxTokens || 2000, 10) || 2000));
    // Диалог (синтетический чат) — массив messages; одиночное задание (практикум) — поле prompt.
    let messages = Array.isArray(body.messages)
      ? body.messages.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
          .map(m => ({ role: m.role, content: m.content }))
      : [{ role: 'user', content: String(body.prompt || '') }];
    const totalChars = messages.reduce((n, m) => n + m.content.length, 0);
    // Режим JSON включён по умолчанию — так работает панель Дельфи практикума; чат передаёт json:false.
    const o = { system, messages, maxTokens, json: body.json !== false, search: body.search === true };
    const isOR = /^or[123]$/.test(provider);
    if (SEARCH[provider]) {
      if (!env.OPENROUTER_KEY) return json({ error: 'в Cloudflare-прокси не добавлен секрет OPENROUTER_KEY' }, 400, req, env);
      if (!messages.length || messages[messages.length - 1].role !== 'user') return json({ error: 'пустой запрос' }, 400, req, env);
      if (totalChars > MAX_PROMPT_CHARS) return json({ error: 'запрос слишком длинный (более ' + MAX_PROMPT_CHARS + ' знаков)' }, 400, req, env);
      try { return json(await callSearch(provider, env, o), 200, req, env); }
      catch (e) { return json({ error: String(e && e.message || e) }, 502, req, env); }
    }
    if (!PROVIDERS[provider] && !isOR) return json({ error: 'неизвестная нейросеть: ' + provider }, 400, req, env);
    if (isOR ? !env.OPENROUTER_KEY : !isConfigured(provider, env)) return json({ error: 'для этой нейросети преподаватель не добавил ключ в прокси' }, 400, req, env);
    if (!messages.length || !messages[0].content.trim() || messages[messages.length - 1].role !== 'user') return json({ error: 'пустой запрос: последним должно идти сообщение пользователя' }, 400, req, env);
    if (totalChars > MAX_PROMPT_CHARS) return json({ error: 'диалог слишком длинный (более ' + MAX_PROMPT_CHARS + ' знаков) — начните новый' }, 400, req, env);

    try {
      const text = await dispatch(provider, env, o);
      const model = isOR ? ((await openRouterModels(env))[+provider[2] - 1] || '') : await modelOf(provider, env);
      return json({ text, model }, 200, req, env);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 502, req, env);
    }
  }
};
