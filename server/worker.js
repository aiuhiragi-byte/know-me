'use strict';
/* 統計トリ🦜 共有API (Cloudflare Workers + D1)
 * 認証はケーパビリティURL方式: 統計ID(推測不可能なランダム文字列)を知っている人だけが読み書きできる。
 * 記録IDはクライアント発行 → INSERT OR IGNORE で再送しても二重登録されない(冪等)。
 */

const LIMITS = {
  title: 60, choiceName: 30, choicesMax: 8, nick: 20,
  idLen: 60, batch: 200, perStat: 20000, ratePerMin: 120,
};

const ORIGIN_RE = [
  /^https:\/\/aiuhiragi-byte\.github\.io$/,
  /^http:\/\/localhost(:\d+)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/,
];

function corsHeaders(req) {
  const o = req.headers.get('Origin') || '';
  return {
    'Access-Control-Allow-Origin': ORIGIN_RE.some(re => re.test(o)) ? o : 'null',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}
const json = (req, data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json', ...corsHeaders(req) },
});
const fail = (req, status, msg) => json(req, { error: msg }, status);

async function sha256(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function randId(n = 22) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const a = crypto.getRandomValues(new Uint8Array(n));
  let s = '';
  for (const x of a) s += chars[x % 62];
  return s;
}

/* 素朴なレート制限(isolate単位のベストエフォート) */
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || now - h.t > 60000) { h = { n: 0, t: now }; hits.set(ip, h); }
  h.n++;
  if (hits.size > 10000) hits.clear();
  return h.n > LIMITS.ratePerMin;
}

function cleanId(v) {
  return (typeof v === 'string' && /^[A-Za-z0-9_-]{1,60}$/.test(v)) ? v : null;
}
function cleanChoices(v) {
  if (!Array.isArray(v) || v.length < 2 || v.length > LIMITS.choicesMax) return null;
  const out = [];
  for (const c of v) {
    const name = (c && typeof c.name === 'string') ? c.name.trim().slice(0, LIMITS.choiceName) : '';
    if (!name) return null;
    out.push({ name, slot: Number.isInteger(c.slot) ? ((c.slot % 8) + 8) % 8 : out.length % 8 });
  }
  return out;
}
function cleanRecord(r, nChoices) {
  const id = cleanId(r && r.id), member = cleanId(r && r.member);
  const c = r && Number.isInteger(r.c) ? r.c : -1;
  const ts = r && Number.isFinite(r.ts) ? Math.floor(r.ts) : NaN;
  if (!id || !member || c < 0 || c >= nChoices) return null;
  if (!(ts > 0 && ts < Date.now() + 86400000)) return null;
  const nick = (r && typeof r.nick === 'string') ? r.nick.slice(0, LIMITS.nick) : '';
  return { id, c, ts, member, nick };
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req) });
    const ip = req.headers.get('CF-Connecting-IP') || 'local';
    if (rateLimited(ip)) return fail(req, 429, 'rate limited');

    const p = new URL(req.url).pathname.split('/').filter(Boolean); // ['api','stats',sid,...]
    if (p[0] !== 'api' || p[1] !== 'stats') return fail(req, 404, 'not found');

    let body = null;
    if (req.method === 'POST' || req.method === 'PATCH') {
      body = await req.json().catch(() => null);
      if (!body) return fail(req, 400, 'bad json');
    }

    try {
      /* POST /api/stats — 共有開始 */
      if (p.length === 2 && req.method === 'POST') {
        const title = (typeof body.title === 'string') ? body.title.trim().slice(0, LIMITS.title) : '';
        const choices = cleanChoices(body.choices);
        const owner = (typeof body.owner === 'string' && body.owner.length >= 16) ? body.owner : null;
        if (!title || !choices || !owner) return fail(req, 400, 'bad request');
        const sid = randId();
        await env.DB.prepare(
          'INSERT INTO stats (id, title, choices, owner_hash, created) VALUES (?,?,?,?,?)')
          .bind(sid, title, JSON.stringify(choices), await sha256(owner), Date.now()).run();
        return json(req, { sid });
      }

      const sid = p.length >= 3 ? cleanId(p[2]) : null;
      if (!sid) return fail(req, 404, 'not found');
      const stat = await env.DB.prepare('SELECT * FROM stats WHERE id = ?').bind(sid).first();
      if (!stat) return fail(req, 404, 'not found');
      if (stat.revoked) return fail(req, 410, 'revoked');
      const choices = JSON.parse(stat.choices);
      const isOwner = async () => typeof body.owner === 'string' && (await sha256(body.owner)) === stat.owner_hash;

      /* GET /api/stats/:sid — 定義+全記録 */
      if (p.length === 3 && req.method === 'GET') {
        const rs = await env.DB.prepare(
          'SELECT id, c, ts, member, nick FROM records WHERE stat_id = ? ORDER BY ts').bind(sid).all();
        return json(req, { title: stat.title, choices, records: rs.results });
      }

      /* PATCH /api/stats/:sid — 定義変更(オーナーのみ) */
      if (p.length === 3 && req.method === 'PATCH') {
        if (!(await isOwner())) return fail(req, 403, 'owner only');
        const title = (typeof body.title === 'string') ? body.title.trim().slice(0, LIMITS.title) : stat.title;
        const newChoices = body.choices ? cleanChoices(body.choices) : choices;
        if (!title || !newChoices || newChoices.length < choices.length) return fail(req, 400, 'bad request');
        await env.DB.prepare('UPDATE stats SET title = ?, choices = ? WHERE id = ?')
          .bind(title, JSON.stringify(newChoices), sid).run();
        return json(req, { ok: true });
      }

      /* POST /api/stats/:sid/revoke — リンク無効化(オーナーのみ) */
      if (p.length === 4 && p[3] === 'revoke' && req.method === 'POST') {
        if (!(await isOwner())) return fail(req, 403, 'owner only');
        await env.DB.prepare('UPDATE stats SET revoked = 1 WHERE id = ?').bind(sid).run();
        return json(req, { ok: true });
      }

      /* POST /api/stats/:sid/records — 記録追加(冪等・まとめ送信可) */
      if (p.length === 4 && p[3] === 'records' && req.method === 'POST') {
        if (!Array.isArray(body.records) || body.records.length > LIMITS.batch) return fail(req, 400, 'bad request');
        const recs = [];
        for (const r of body.records) {
          const rec = cleanRecord(r, choices.length);
          if (!rec) return fail(req, 400, 'bad record');
          recs.push(rec);
        }
        const cnt = await env.DB.prepare('SELECT COUNT(*) AS n FROM records WHERE stat_id = ?').bind(sid).first();
        if (cnt.n + recs.length > LIMITS.perStat) return fail(req, 413, 'too many records');
        if (recs.length) {
          const stmt = env.DB.prepare(
            'INSERT OR IGNORE INTO records (id, stat_id, c, ts, member, nick) VALUES (?,?,?,?,?,?)');
          await env.DB.batch(recs.map(r => stmt.bind(r.id, sid, r.c, r.ts, r.member, r.nick)));
        }
        return json(req, { ok: true, count: recs.length });
      }

      /* PATCH /api/stats/:sid/records/:rid — 自分の記録の修正 */
      if (p.length === 5 && p[3] === 'records' && req.method === 'PATCH') {
        const rid = cleanId(p[4]), member = cleanId(body.member);
        if (!rid || !member) return fail(req, 400, 'bad request');
        const cur = await env.DB.prepare('SELECT c, ts FROM records WHERE stat_id = ? AND id = ? AND member = ?')
          .bind(sid, rid, member).first();
        if (!cur) return fail(req, 404, 'record not found');
        const c = Number.isInteger(body.c) && body.c >= 0 && body.c < choices.length ? body.c : cur.c;
        const ts = Number.isFinite(body.ts) && body.ts > 0 && body.ts < Date.now() + 86400000 ? Math.floor(body.ts) : cur.ts;
        await env.DB.prepare('UPDATE records SET c = ?, ts = ? WHERE stat_id = ? AND id = ? AND member = ?')
          .bind(c, ts, sid, rid, member).run();
        return json(req, { ok: true });
      }

      /* DELETE /api/stats/:sid/records/:rid?member=... — 自分の記録の削除 */
      if (p.length === 5 && p[3] === 'records' && req.method === 'DELETE') {
        const rid = cleanId(p[4]);
        const member = cleanId(new URL(req.url).searchParams.get('member'));
        if (!rid || !member) return fail(req, 400, 'bad request');
        await env.DB.prepare('DELETE FROM records WHERE stat_id = ? AND id = ? AND member = ?')
          .bind(sid, rid, member).run();
        return json(req, { ok: true });
      }

      return fail(req, 404, 'not found');
    } catch (e) {
      return fail(req, 500, 'server error');
    }
  },
};
