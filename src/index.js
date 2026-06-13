const enc = new TextEncoder();
const dec = new TextDecoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get("Cookie") || "");

    // The entry parameter names and values exist only in Worker secrets.
    if (
      request.method === "GET" &&
      url.pathname === "/" &&
      env.ENTRY_PARAM &&
      env.ENTRY_TOKEN &&
      url.searchParams.get(env.ENTRY_PARAM) === env.ENTRY_TOKEN
    ) {
      const gate = await makeToken({ kind: "gate", exp: now() + 300 }, env.SESSION_SECRET);
      return redirect("/", [cookie("math_gate", gate, 300)]);
    }

    const session = await readToken(cookies.math_session, env.SESSION_SECRET, "session");
    const gate = await readToken(cookies.math_gate, env.SESSION_SECRET, "gate");

    if (request.method === "POST" && url.pathname === "/") {
      if (!sameOrigin(request)) return plain("Forbidden", 403);
      const form = await request.formData();

      if (session && form.get("_action") === "logout") {
        return redirect("/", [cookie("math_session", "", 0), cookie("math_gate", "", 0)]);
      }

      if (!gate) return plain("Not found", 404);

      const password = String(form.get("password") || "");
      if (!env.AUTH_PASSWORD || !safeEqual(password, env.AUTH_PASSWORD)) {
        return html(loginPage("パスワードが違います。"), 401);
      }

      const token = await makeToken({ kind: "session", exp: now() + 60 * 60 * 8 }, env.SESSION_SECRET);
      return redirect("/", [cookie("math_session", token, 60 * 60 * 8), cookie("math_gate", "", 0)]);
    }

    if (request.method !== "GET" || url.pathname !== "/") return plain("Not found", 404);
    if (session) return html(secretPage());
    if (gate) return html(loginPage());
    return html(publicPage(), 200, true);
  }
};

function now() { return Math.floor(Date.now() / 1000); }

async function makeToken(payload, secret) {
  if (!secret) throw new Error("SESSION_SECRET is not configured");
  const body = b64url(enc.encode(JSON.stringify(payload)));
  return `${body}.${await sign(body, secret)}`;
}

async function readToken(token, secret, kind) {
  if (!token || !secret) return null;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra) return null;
  const expected = await sign(body, secret);
  if (!safeEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(dec.decode(unb64url(body)));
    return payload.kind === kind && Number.isFinite(payload.exp) && payload.exp >= now() ? payload : null;
  } catch { return null; }
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value))));
}

function safeEqual(a, b) {
  const aa = enc.encode(String(a));
  const bb = enc.encode(String(b));
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) diff |= (aa[i] || 0) ^ (bb[i] || 0);
  return diff === 0;
}

function b64url(bytes) {
  let s = "";
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function unb64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(normalized), c => c.charCodeAt(0));
}

function parseCookies(header) {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}

function baseHeaders(contentType) {
  return {
    "Content-Type": contentType,
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  };
}

function html(body, status = 200) {
  return new Response(body, { status, headers: baseHeaders("text/html; charset=UTF-8") });
}

function plain(body, status = 200) {
  return new Response(body, { status, headers: baseHeaders("text/plain; charset=UTF-8") });
}

function redirect(location, cookies = []) {
  const headers = new Headers(baseHeaders("text/plain; charset=UTF-8"));
  headers.set("Location", location);
  for (const value of cookies) headers.append("Set-Cookie", value);
  return new Response(null, { status: 303, headers });
}

function publicPage() {
  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Math Atlas — 中学数学の要点集</title><meta name="description" content="中学数学を、公式・図解・例題で一気に復習できる学習サイト。">
<style>
:root{--ink:#172033;--muted:#667085;--paper:#f5f7fb;--card:#fff;--blue:#3157d5;--cyan:#1bb4c8;--line:#e5e9f2;--shadow:0 18px 60px rgba(31,45,76,.10)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;color:var(--ink);font-family:Inter,"Noto Sans JP",system-ui,sans-serif;background:radial-gradient(circle at 85% -5%,#d8e7ff 0,transparent 30%),radial-gradient(circle at 0 25%,#d9fbf5 0,transparent 24%),var(--paper);line-height:1.75}a{color:inherit;text-decoration:none}.wrap{width:min(1120px,calc(100% - 34px));margin:auto}header{position:sticky;top:0;z-index:10;background:rgba(245,247,251,.82);backdrop-filter:blur(16px);border-bottom:1px solid rgba(229,233,242,.8)}nav{height:68px;display:flex;align-items:center;justify-content:space-between}.brand{font-size:19px;font-weight:900;letter-spacing:-.03em}.brand i{display:inline-grid;place-items:center;width:32px;height:32px;margin-right:9px;border-radius:10px;color:#fff;background:linear-gradient(135deg,var(--blue),var(--cyan));font-style:normal}.links{display:flex;gap:24px;font-size:14px;font-weight:700;color:#475467}.hero{padding:92px 0 68px;display:grid;grid-template-columns:1.15fr .85fr;gap:48px;align-items:center}.eyebrow{display:inline-flex;gap:8px;align-items:center;padding:7px 12px;border:1px solid #cbd8ff;border-radius:999px;background:#fff;color:#3157d5;font-size:12px;font-weight:800}.dot{width:7px;height:7px;border-radius:50%;background:#32c7a2;box-shadow:0 0 0 5px #daf8ef}h1{margin:22px 0 18px;font-size:clamp(44px,7vw,82px);line-height:1.02;letter-spacing:-.07em}.grad{color:transparent;background:linear-gradient(90deg,#3157d5,#17a8bc);background-clip:text}.lead{max-width:650px;color:#596579;font-size:18px}.actions{display:flex;gap:12px;margin-top:30px}.btn{display:inline-flex;align-items:center;justify-content:center;padding:13px 20px;border-radius:13px;font-weight:800}.primary{color:#fff;background:#172033;box-shadow:0 10px 28px #17203333}.secondary{background:#fff;border:1px solid var(--line)}.board{position:relative;min-height:390px;padding:28px;border:1px solid #fff;border-radius:28px;background:linear-gradient(145deg,#172033,#263a69);box-shadow:var(--shadow);color:#fff;overflow:hidden}.board:before{content:"";position:absolute;inset:0;background-image:linear-gradient(#ffffff0c 1px,transparent 1px),linear-gradient(90deg,#ffffff0c 1px,transparent 1px);background-size:28px 28px}.formula{position:relative;font-family:Georgia,serif}.formula.big{font-size:42px;margin:40px 0 8px}.formula.small{color:#bfe9ff;font-size:21px}.graph{position:absolute;right:-20px;bottom:-10px;width:250px;height:250px;border-left:2px solid #ffffff80;border-bottom:2px solid #ffffff80;transform:rotate(-8deg)}.curve{position:absolute;width:200px;height:125px;right:16px;bottom:24px;border:3px solid #5ee4cb;border-color:#5ee4cb transparent transparent #5ee4cb;border-radius:50%;transform:rotate(24deg)}.section{padding:64px 0}.section-head{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:24px}.section h2{margin:0;font-size:34px;letter-spacing:-.04em}.section-head p{margin:0;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.card{position:relative;padding:24px;border:1px solid var(--line);border-radius:20px;background:rgba(255,255,255,.88);box-shadow:0 8px 30px rgba(31,45,76,.05);transition:.25s}.card:hover{transform:translateY(-5px);box-shadow:var(--shadow)}.num{font-size:12px;font-weight:900;color:#3157d5}.card h3{margin:8px 0 8px;font-size:21px}.card p{margin:0;color:var(--muted);font-size:14px}.tag{display:inline-block;margin-top:18px;padding:5px 9px;border-radius:8px;background:#edf1ff;color:#3157d5;font-size:11px;font-weight:800}.formula-box{margin-top:16px;padding:14px;border-radius:12px;background:#f7f9fd;font-family:Georgia,serif;text-align:center;font-size:18px}.quick{display:grid;grid-template-columns:1fr 1fr;gap:20px}.panel{padding:28px;border-radius:22px;background:#fff;border:1px solid var(--line)}.quiz-q{font-weight:800;font-size:18px}.choices{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:18px}.choice{padding:12px;border:1px solid var(--line);border-radius:11px;background:#fff;font:inherit;cursor:pointer}.choice:hover{border-color:#3157d5}.result{min-height:28px;margin-top:12px;font-weight:800}.checklist{display:grid;gap:11px}.check{display:flex;gap:12px;align-items:center;padding:13px;border-radius:12px;background:#f7f9fd}.check b{display:grid;place-items:center;width:27px;height:27px;border-radius:8px;background:#e0f8f0;color:#11866d}.search{width:100%;padding:15px 18px;border:1px solid var(--line);border-radius:14px;background:#fff;font:inherit;outline:none}.search:focus{border-color:#3157d5;box-shadow:0 0 0 4px #3157d519}footer{padding:50px 0;color:var(--muted);font-size:13px;border-top:1px solid var(--line)}@media(max-width:820px){.links{display:none}.hero{grid-template-columns:1fr;padding-top:60px}.board{min-height:300px}.grid{grid-template-columns:1fr}.quick{grid-template-columns:1fr}.section-head{display:block}.section-head p{margin-top:8px}.choices{grid-template-columns:1fr}}
</style></head><body>
<header><nav class="wrap"><a class="brand" href="#"><i>∑</i>Math Atlas</a><div class="links"><a href="#units">単元</a><a href="#review">復習</a><a href="#quiz">1分テスト</a></div></nav></header>
<main><section class="hero wrap"><div><span class="eyebrow"><span class="dot"></span>中学3年間を、ひとつの地図に。</span><h1>数学は、<br><span class="grad">つながると解ける。</span></h1><p class="lead">公式をただ暗記するのではなく、「なぜそうなるか」と「どこで使うか」を短く整理。定期テストから高校数学の入口まで、迷わず復習できます。</p><div class="actions"><a class="btn primary" href="#units">単元を見る →</a><a class="btn secondary" href="#quiz">実力チェック</a></div></div><div class="board"><div class="formula big">y = ax²</div><div class="formula small">a² + b² = c²</div><div class="formula" style="margin-top:70px;font-size:25px">(x + a)(x + b)</div><div class="graph"><div class="curve"></div></div></div></section>
<section class="section wrap" id="units"><div class="section-head"><div><span class="num">CURRICULUM</span><h2>単元から探す</h2></div><p>カードを検索して、復習したい場所へ。</p></div><input id="search" class="search" placeholder="例：方程式、関数、図形、確率…" aria-label="単元を検索"><div class="grid" id="cards" style="margin-top:18px">
${unitCard("01","正負の数・文字式","数の符号、絶対値、文字を使った式のルール。","a(b+c)=ab+ac","数と式")}
${unitCard("02","方程式","移項の意味から連立方程式、文章題まで。","ax+b=c","方程式")}
${unitCard("03","比例・反比例","変化の割合を表、式、グラフでつなぐ。","y=ax / y=a÷x","関数")}
${unitCard("04","一次関数","傾きと切片、交点、動点問題の見方。","y=ax+b","関数")}
${unitCard("05","平方根・二次方程式","根号計算、因数分解、解の公式を整理。","x=(-b±√(b²-4ac))/2a","数と式")}
${unitCard("06","図形と証明","合同・相似・円・三平方を論理で結ぶ。","a²+b²=c²","図形")}
${unitCard("07","確率・データ","場合の数、確率、代表値、箱ひげ図。","確率=起こる場合÷全体","資料")}
${unitCard("08","二次関数","放物線の特徴と変域、図形との融合。","y=ax²","関数")}
${unitCard("09","空間図形","表面積・体積と、立体の切断をイメージ。","V=1/3×底面積×高さ","図形")}
</div></section>
<section class="section wrap" id="review"><div class="section-head"><div><span class="num">FAST REVIEW</span><h2>テスト前の最終確認</h2></div></div><div class="quick"><div class="panel"><div class="checklist"><div class="check"><b>1</b><span><strong>式変形</strong><br><small>両辺に同じ操作をしているか</small></span></div><div class="check"><b>2</b><span><strong>関数</strong><br><small>xとyの対応を式で表せるか</small></span></div><div class="check"><b>3</b><span><strong>証明</strong><br><small>仮定・根拠・結論がつながっているか</small></span></div><div class="check"><b>4</b><span><strong>見直し</strong><br><small>符号、単位、答え方を確認したか</small></span></div></div></div><div class="panel" id="quiz"><span class="num">60 SECOND QUIZ</span><p class="quiz-q">一次関数 y = 3x − 2 で、xが2増えるとyはいくつ増える？</p><div class="choices"><button class="choice" data-ok="0">2</button><button class="choice" data-ok="0">3</button><button class="choice" data-ok="1">6</button><button class="choice" data-ok="0">8</button></div><div id="result" class="result" aria-live="polite"></div></div></div></section></main>
<footer><div class="wrap">© 2026 Math Atlas · 中学数学の学び直しノート</div></footer>
<script>const q=document.querySelector('#search'),cards=[...document.querySelectorAll('.card')];q.addEventListener('input',()=>{const v=q.value.toLowerCase();cards.forEach(c=>c.style.display=c.textContent.toLowerCase().includes(v)?'block':'none')});document.querySelectorAll('.choice').forEach(b=>b.onclick=()=>{document.querySelector('#result').textContent=b.dataset.ok==='1'?'正解！ 傾き3 × xの増加量2 = 6':'惜しい。変化の割合（傾き）に注目！'});</script></body></html>`;
}

function unitCard(no, title, text, formula, tag) {
  return `<article class="card"><span class="num">${no}</span><h3>${title}</h3><p>${text}</p><div class="formula-box">${formula}</div><span class="tag">${tag}</span></article>`;
}

function loginPage(error = "") {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Math Atlas</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f5fa;color:#172033;font-family:system-ui,sans-serif}.box{width:min(410px,calc(100% - 32px));padding:34px;border-radius:22px;background:#fff;border:1px solid #e5e9f2;box-shadow:0 24px 70px #1f2d4c18}.mark{width:48px;height:48px;display:grid;place-items:center;border-radius:14px;color:#fff;background:linear-gradient(135deg,#3157d5,#1bb4c8);font-size:22px;font-weight:900}h1{margin:22px 0 5px;font-size:25px}p{margin:0 0 24px;color:#667085}label{display:block;margin-bottom:8px;font-size:13px;font-weight:800}input{width:100%;padding:14px;border:1px solid #d9deea;border-radius:12px;font:inherit;outline:none}input:focus{border-color:#3157d5;box-shadow:0 0 0 4px #3157d51a}button{width:100%;margin-top:13px;padding:14px;border:0;border-radius:12px;background:#172033;color:#fff;font:inherit;font-weight:800;cursor:pointer}.error{padding:10px 12px;border-radius:10px;background:#fff0f0;color:#b42318;font-size:13px}</style></head><body><main class="box"><div class="mark">∑</div><h1>続きにアクセス</h1><p>認証情報を入力してください。</p>${error ? `<div class="error">${error}</div>` : ""}<form method="post" action="/"><label for="password">パスワード</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button>ログイン</button></form></main></body></html>`;
}

function secretPage() {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Workspace</title><style>*{box-sizing:border-box}body{margin:0;background:#0d1320;color:#e8edf7;font-family:system-ui,sans-serif}.wrap{width:min(980px,calc(100% - 32px));margin:auto}header{border-bottom:1px solid #ffffff18}nav{height:68px;display:flex;align-items:center;justify-content:space-between}.brand{font-weight:900}button{padding:9px 14px;border:1px solid #ffffff22;border-radius:10px;background:#ffffff0c;color:#fff;cursor:pointer}.hero{padding:85px 0 40px}small{color:#63e6c4;font-weight:800;letter-spacing:.15em}h1{font-size:clamp(40px,8vw,74px);margin:12px 0;letter-spacing:-.06em}.muted{color:#9ca9bf}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;padding:25px 0 80px}.card{min-height:170px;padding:22px;border:1px solid #ffffff15;border-radius:18px;background:linear-gradient(145deg,#182238,#111a2b)}.card b{font-size:20px}.card p{color:#9ca9bf}@media(max-width:700px){.grid{grid-template-columns:1fr}}</style></head><body><header><nav class="wrap"><div class="brand">PRIVATE WORKSPACE</div><form method="post" action="/"><input type="hidden" name="_action" value="logout"><button>ログアウト</button></form></nav></header><main class="wrap"><section class="hero"><small>AUTHENTICATED</small><h1>Welcome back.</h1><p class="muted">このページの内容を、用途に合わせて自由に置き換えてください。</p></section><section class="grid"><div class="card"><b>Notes</b><p>個人用のメモやリンクを配置できます。</p></div><div class="card"><b>Files</b><p>R2などと接続すればファイル置き場にもできます。</p></div><div class="card"><b>Tools</b><p>Worker内のAPIや小さなツールを追加できます。</p></div></section></main></body></html>`;
}
