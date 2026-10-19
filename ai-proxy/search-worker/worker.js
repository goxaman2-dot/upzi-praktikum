// =====================================================================
// Прокси поиска для сайта «Поиск в 4 канала» (Cloudflare Workers).
// Все каналы идут через OpenRouter — нужен один ключ, оплата с баланса OpenRouter.
//
// Переменные (Settings → Variables and Secrets):
//   OPENROUTER_API_KEY — ключ OpenRouter (секрет), обязателен
//   ACCESS_CODE        — код доступа (тот же, что в синтетическом чате), рекомендуется
// Необязательные — имена моделей из каталога OpenRouter:
//   PERPLEXITY_MODEL   (по умолчанию perplexity/sonar-pro)
//   PERPLEXITY_R_MODEL (по умолчанию perplexity/sonar-reasoning-pro)
//   GEMINI_MODEL       (по умолчанию google/gemini-3.8-flash, веб-поиск включается суффиксом :online)
//   DEEPSEEK_MODEL     (по умолчанию deepseek/deepseek-v4.1-flash, режим рассуждения включён)
// Адреса: GET /status — какие каналы готовы; POST /chat — запрос.
// =====================================================================
const OR_URL = 'https://openrouter.ai/api/v1/chat/completions';
const MAX_TOKENS = 8000, MAX_CHARS = 150000;
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Access-Code',
  'Access-Control-Max-Age': '86400'
};
const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, CORS) });

const models = env => ({
  perplexity:   env.PERPLEXITY_MODEL   || 'perplexity/sonar-pro',
  perplexity_r: env.PERPLEXITY_R_MODEL || 'perplexity/sonar-reasoning-pro',
  gemini:      (env.GEMINI_MODEL       || 'google/gemini-3.8-flash').replace(/:online$/, ''),
  deepseek:     env.DEEPSEEK_MODEL     || 'deepseek/deepseek-v4.1-flash'
});

function cleanSites(list, max) {
  if (!Array.isArray(list)) return [];
  return list.map(s => String(s || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
    .filter(s => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)).slice(0, max);
}
// Perplexity требует строгого чередования user/assistant.
function alternate(msgs) {
  const out = [];
  msgs.forEach(m => {
    if (out.length && out[out.length - 1].role === m.role) out[out.length - 1].content += '\n\n' + m.content;
    else out.push({ role: m.role, content: m.content });
  });
  while (out.length && out[0].role !== 'user') out.shift();
  return out;
}
function errText(name, status, text) {
  let msg = text;
  try { const j = JSON.parse(text); msg = (j.error && (j.error.message || j.error)) || j.message || text; } catch (e) {}
  return name + ': ' + String(msg || ('HTTP ' + status)).slice(0, 300);
}
// Временные сбои (обрыв у провайдера, 5xx, 408, 429) повторяем один раз через 2 с.
async function orSendOnce(env, payload) {
  try {
    const r = await fetch(OR_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + env.OPENROUTER_API_KEY, 'X-Title': 'Poisk v 4 kanala' },
      body: JSON.stringify(payload)
    });
    const text = await r.text();
    // OpenRouter иногда отвечает 200, но с ошибкой провайдера внутри тела.
    if (r.status === 200 && /"error"\s*:/.test(text) && !/"choices"\s*:/.test(text)) return { status: 502, text };
    return { status: r.status, text };
  } catch (e) { return { status: 599, text: JSON.stringify({ error: { message: String(e && e.message || e) } }) }; }
}
const transient = st => st >= 500 || st === 408 || st === 429;
async function orSend(env, payload) {
  let r = await orSendOnce(env, payload);
  if (transient(r.status)) { await new Promise(ok => setTimeout(ok, 2000)); r = await orSendOnce(env, payload); }
  return r;
}
// Источники: search_results / citations (Perplexity) или аннотации url_citation (OpenRouter).
function sourcesOf(j) {
  const m = (j.choices && j.choices[0] && j.choices[0].message) || {};
  let out = [];
  if (Array.isArray(j.search_results) && j.search_results.length) out = j.search_results.map(s => ({ url: s.url, title: s.title || '', date: s.date || '' }));
  else if (Array.isArray(j.citations) && j.citations.length) out = j.citations.map(c => typeof c === 'string' ? { url: c, title: '' } : { url: c.url, title: c.title || '' });
  else out = (m.annotations || []).filter(a => a && a.url_citation).map(a => ({ url: a.url_citation.url, title: a.url_citation.title || '' }));
  const seen = new Set();
  return out.filter(s => s.url && !seen.has(s.url) && seen.add(s.url));
}
// Ссылки вида [название](https://…) прямо из текста ответа.
function mdLinks(text) {
  const out = [], re = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g; let m;
  while ((m = re.exec(String(text || '')))) out.push({ url: m[2], title: m[1] });
  return out;
}
// Gemini отдаёт источники как переадресации vertexaisearch.cloud.google.com — раскрываем до настоящего адреса.
async function resolveRedirects(list) {
  return Promise.all(list.map(async s => {
    if (!/grounding-api-redirect/.test(s.url)) return s;
    try {
      const r = await fetch(s.url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(5000) });
      const loc = r.headers.get('location');
      return loc ? { url: loc, title: s.title || '' } : s;
    } catch (e) { return s; }
  }));
}
function mergeSources(a, b) {
  const seen = new Set(), out = [];
  a.concat(b).forEach(s => { const k = s.url.replace(/\/+$/, ''); if (s.url && !seen.has(k)) { seen.add(k); out.push(s); } });
  return out;
}
const msgOf = j => (j.choices && j.choices[0] && j.choices[0].message) || {};
// Модели рассуждения Perplexity иногда пишут ход мысли в <think>…</think> прямо в ответ — выносим отдельно.
function splitThink(text) {
  const m = String(text || '').match(/^\s*<think>([\s\S]*?)<\/think>\s*/);
  return m ? { text: text.slice(m[0].length), think: m[1].trim() } : { text, think: '' };
}

async function callPerplexity(env, o, body, model) {
  const base = { model, max_tokens: o.maxTokens, messages: (o.system ? [{ role: 'system', content: o.system }] : []).concat(alternate(o.messages)) };
  const extra = {};
  if (body.academic) extra.search_mode = 'academic';
  const dom = cleanSites(body.domains, 20);
  if (dom.length) extra.search_domain_filter = dom;
  let r = await orSend(env, Object.assign({}, base, extra));
  if (r.status === 400 && Object.keys(extra).length) r = await orSend(env, base);   // фильтры не приняты — без них
  if (r.status !== 200) throw new Error(errText('Perplexity (' + model + ')', r.status, r.text));
  const j = JSON.parse(r.text), m = msgOf(j), st = splitThink(m.content);
  return { text: st.text, reasoning: m.reasoning || st.think || '', sources: sourcesOf(j), model: j.model || model };
}

async function callGemini(env, o, model) {
  const msgs = (o.system ? [{ role: 'system', content: o.system }] : []).concat(o.messages);
  const tries = [{ model: model + ':online' }, { model, plugins: [{ id: 'web' }] }, { model, noSearch: true }];
  let last;
  for (const t of tries) {
    const p = { model: t.model, max_tokens: o.maxTokens, messages: msgs };
    if (t.plugins) p.plugins = t.plugins;
    const r = await orSend(env, p);
    if (r.status === 200) {
      const j = JSON.parse(r.text);
      const text = msgOf(j).content || '';
      const src = mergeSources(mdLinks(text), await resolveRedirects(sourcesOf(j)));
      return { text, sources: src, model: (j.model || t.model) + (t.noSearch ? ' · без веб-поиска, ответ по памяти' : ' · веб-поиск') };
    }
    last = r;
    // Неподдерживаемый вариант или повторный сбой — пробуем следующий способ включить поиск.
    if (r.status !== 400 && r.status !== 404 && r.status !== 422 && !transient(r.status)) break;
  }
  throw new Error(errText('Gemini (' + model + ')', last.status, last.text));
}

async function callDeepSeek(env, o, model) {
  const msgs = (o.system ? [{ role: 'system', content: o.system }] : []).concat(o.messages);
  // Запас токенов: рассуждение расходует их до ответа.
  const mt = Math.min(o.maxTokens + 12000, 32000);
  let r = await orSend(env, { model, messages: msgs, max_tokens: mt, reasoning: { effort: 'high' } });
  if (r.status === 400 || r.status === 422) r = await orSend(env, { model, messages: msgs, max_tokens: mt });
  if (r.status !== 200) throw new Error(errText('DeepSeek (' + model + ')', r.status, r.text));
  const j = JSON.parse(r.text), m = msgOf(j);
  const reasoning = m.reasoning || m.reasoning_content || '';
  if (!m.content && reasoning) throw new Error('DeepSeek израсходовал лимит на рассуждение и не успел дать ответ. Нажмите «Повторить».');
  return { text: m.content || '', reasoning, model: j.model || model };
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url);
    const codeOk = !env.ACCESS_CODE || req.headers.get('X-Access-Code') === env.ACCESS_CODE;
    const key = !!env.OPENROUTER_API_KEY, M = models(env);

    if (req.method === 'GET') {
      const pv = (id, extra) => Object.assign({ configured: key, model: M[id], via: 'OpenRouter' }, extra || {});
      return json(200, {
        ok: true, accessCodeRequired: !!env.ACCESS_CODE, accessCodeOk: codeOk,
        providers: { perplexity: pv('perplexity'), perplexity_r: pv('perplexity_r'), gemini: pv('gemini'), deepseek: pv('deepseek', { thinking: true }) }
      });
    }
    if (req.method !== 'POST' || !/\/chat\/?$/.test(url.pathname)) return json(404, { error: 'используйте GET /status или POST /chat' });
    if (!codeOk) return json(401, { error: 'неверный или отсутствующий код доступа' });
    if (!key) return json(400, { error: 'в воркер не добавлен OPENROUTER_API_KEY' });

    let body;
    try { body = await req.json(); } catch (e) { return json(400, { error: 'тело запроса — не JSON' }); }
    const messages = Array.isArray(body.messages)
      ? body.messages.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim()).map(m => ({ role: m.role, content: m.content }))
      : [];
    if (!messages.length || messages[messages.length - 1].role !== 'user') return json(400, { error: 'пустой запрос' });
    if (messages.reduce((n, m) => n + m.content.length, 0) > MAX_CHARS) return json(400, { error: 'диалог слишком длинный — начните новый' });
    const o = { system: String(body.system || '').slice(0, 8000), messages, maxTokens: Math.min(MAX_TOKENS, Math.max(64, parseInt(body.maxTokens || 4000, 10) || 4000)) };

    try {
      switch (String(body.provider || '')) {
        case 'perplexity':   return json(200, await callPerplexity(env, o, body, M.perplexity));
        case 'perplexity_r': return json(200, await callPerplexity(env, o, body, M.perplexity_r));
        case 'gemini':       return json(200, await callGemini(env, o, M.gemini));
        case 'deepseek':     return json(200, await callDeepSeek(env, o, M.deepseek));
        default:             return json(400, { error: 'неизвестный канал: ' + body.provider });
      }
    } catch (e) {
      return json(502, { error: String(e && e.message || e) });
    }
  }
};
