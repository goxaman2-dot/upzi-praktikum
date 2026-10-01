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
//   ACCESS_CODE     — код доступа для студентов (если задан, без него прокси не отвечает)
// Переменные (Type: Text), тоже необязательны:
//   ALLOWED_ORIGINS — через запятую; по умолчанию сайт практикума + локальный файл (null)
//   CLAUDE_MODEL, QWEN_MODEL, DEEPSEEK_MODEL, GEMINI_MODEL, GIGACHAT_MODEL, GIGACHAT_SCOPE
//   RATE_LIMIT      — запросов с одного IP за 10 минут (по умолчанию 300 — в классе все компьютеры часто выходят через один IP)
// =====================================================================

const DEFAULT_ORIGINS = 'https://goxaman2-dot.github.io,null';
const MAX_PROMPT_CHARS = 150000;
const MAX_TOKENS = 8000;
const WINDOW_MS = 10 * 60 * 1000;

const PROVIDERS = {
  claude:   { key: 'CLAUDE_KEY',    model: env => env.CLAUDE_MODEL   || 'claude-haiku-4-5-20251001' },
  qwen:     { key: 'QWEN_KEY',      model: env => env.QWEN_MODEL     || 'qwen-plus' },
  deepseek: { key: 'DEEPSEEK_KEY',  model: env => env.DEEPSEEK_MODEL || 'deepseek-chat' },
  gemini:   { key: 'GEMINI_KEY',    model: env => env.GEMINI_MODEL   || 'gemini-2.5-flash' },
  gigachat: { key: 'GIGACHAT_AUTH', model: env => env.GIGACHAT_MODEL || 'GigaChat' }
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
  try { const j = JSON.parse(t); msg = (j.error && (j.error.message || j.error)) || j.message || t; } catch (e) {}
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

async function callOpenAICompatible(url, key, model, o, name, extra) {
  const msgs = (o.system ? [{ role: 'system', content: o.system }] : []).concat(o.messages);
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key },
    body: JSON.stringify(Object.assign({ model, temperature: o.json ? 0.2 : 0.5, max_tokens: o.maxTokens, messages: msgs }, extra || {}))
  });
  if (!r.ok) throw new Error(await readError(r, name));
  const j = await r.json();
  return (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '';
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

async function dispatch(provider, env, o) {
  const jsonMode = o.json ? { response_format: { type: 'json_object' } } : {};
  switch (provider) {
    case 'claude':   return callClaude(env, o);
    case 'qwen':     return callOpenAICompatible('https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions', env.QWEN_KEY, PROVIDERS.qwen.model(env), o, 'Qwen',
                       o.search ? { enable_search: true } : jsonMode);
    case 'deepseek': return callOpenAICompatible('https://api.deepseek.com/chat/completions', env.DEEPSEEK_KEY, PROVIDERS.deepseek.model(env), o, 'DeepSeek', jsonMode);
    case 'gemini':   return callGemini(env, o);
    case 'gigachat': return callGigaChat(env, o);
  }
  throw new Error('неизвестная нейросеть: ' + provider);
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req, env) });
    if (!originAllowed(req, env)) return json({ error: 'запрос с этого сайта не разрешён (ALLOWED_ORIGINS)' }, 403, req, env);

    const url = new URL(req.url);
    const codeOk = !env.ACCESS_CODE || req.headers.get('X-Access-Code') === env.ACCESS_CODE;

    if (req.method === 'GET' && url.pathname.replace(/\/+$/, '') === '/status') {
      const providers = {};
      for (const [id, p] of Object.entries(PROVIDERS)) providers[id] = { configured: !!env[p.key], model: p.model(env) };
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
    if (!PROVIDERS[provider]) return json({ error: 'неизвестная нейросеть: ' + provider }, 400, req, env);
    if (!env[PROVIDERS[provider].key]) return json({ error: 'для этой нейросети преподаватель не добавил ключ в прокси' }, 400, req, env);
    if (!messages.length || !messages[0].content.trim() || messages[messages.length - 1].role !== 'user') return json({ error: 'пустой запрос: последним должно идти сообщение пользователя' }, 400, req, env);
    if (totalChars > MAX_PROMPT_CHARS) return json({ error: 'диалог слишком длинный (более ' + MAX_PROMPT_CHARS + ' знаков) — начните новый' }, 400, req, env);

    try {
      const text = await dispatch(provider, env, o);
      return json({ text, model: PROVIDERS[provider].model(env) }, 200, req, env);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 502, req, env);
    }
  }
};
