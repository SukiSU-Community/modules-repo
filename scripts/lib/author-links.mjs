/**
 * author-links.mjs
 *
 * 「作者主页」两格的归一化判据（契约 §3.1 / §3.2）。
 *
 * 生产端是 `scripts/build-index.mjs`（把投稿条目里的声明投影进公开索引），校验端是
 * `scripts/validate-index.mjs`（确认一份索引里的值**已经是**归一化形状）。两边共用一个实现，
 * 因为这两条判据有一半不是「一句正则」能说清的东西 —— GitHub 的保留路径
 * （`github.com/topics` 不是某人的主页）、连续连字符、`.git`、酷安的多段路径。
 * 两份拷贝必然会漂，而 §5.4 要求校验器与生产端「做同样的校验」，共享实现是唯一能保证
 * 「同样」的写法。
 *
 * 为什么索引侧还要再验一遍（而不是信任 Worker 的投稿入口）：`json/modules.json` 是公开产物，
 * 网页与 App 会把这些字符串渲染成可点链接。只要上游漏一处校验，或者有人手改索引，
 * 一个 `javascript:…` / 伪装域名就会原样发出去 —— 判据不能只有生产者一份。
 *
 * 只允许 node: 内置模块（本仓库硬性约束）—— 这个文件连内置模块都不需要。
 */

/** 酷安 UID：4–12 位纯数字（与契约 §2 / dispositions.mjs 的 UID_RE 同一形状）。 */
const UID_RE = /^[0-9]{4,12}$/;
/**
 * GitHub login：1–39 位 `[A-Za-z0-9-]`，首尾不能是连字符。
 * 连续 `--` 不在正则里查（负向前瞻写在这里只会更难读），由调用方单独判。
 */
const GITHUB_LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

/**
 * GitHub 的保留顶层路径（契约 §3.2）。
 *
 * 前 14 个是契约明列的；其余是 GitHub 自己的功能路由 —— 它们同样不可能是某个人的主页，
 * 放行只会让界面上一行标题写着「作者主页」的链接点到一个导航页。判断用
 * `login.toLowerCase()`：GitHub 的 login 大小写不敏感，`GitHub.com/Topics` 与 `/topics` 是同一页。
 */
const GITHUB_RESERVED_LOGINS = new Set([
  // 契约 §3.2 明列 + 与 Worker/网页共用的同一张表（76 项，全部小写）
  'about', 'account', 'admin', 'api', 'apps', 'blog', 'business', 'codespaces', 'collections',
  'contact', 'customer-stories', 'dashboard', 'developer', 'discussions', 'download', 'downloads',
  'edu', 'education', 'enterprise', 'events', 'explore', 'features', 'followers', 'following',
  'gist', 'git', 'git-guides', 'github', 'help', 'home', 'hovercards', 'issues', 'join', 'login',
  'logout', 'marketplace', 'mobile', 'new', 'nonprofit', 'notifications', 'open-source',
  'organizations', 'orgs', 'pages', 'partners', 'personal', 'plans', 'prebuilds', 'pricing',
  'privacy', 'projects', 'pulls', 'readme', 'resources', 'search', 'security', 'sessions',
  'settings', 'shop', 'showcases', 'signup', 'site', 'solutions', 'sponsors', 'stars', 'status',
  'team', 'teams', 'terms', 'topics', 'trending', 'users', 'watching', 'welcome', 'wiki',
  'workflows',
]);

/**
 * 把「像不像一个地址」的裸串补上 scheme —— 契约 §3.1 / §3.2 都允许 `coolapk.com/u/1`、
 * `github.com/octocat` 这种不带协议的输入。
 *
 * 只在**完全没有 scheme** 时补（`^scheme://`）；`javascript:alert(1)` 这种带 `:` 但没 `//`
 * 的串补成 `https://javascript:alert(1)` 之后，authority 里的那个 `:` 会先被
 * `hasExplicitPortOrUserinfo` 当成端口拦下，所以它不会借这条捷径溜过去。
 * 带 scheme 的原样交给 URL 解析，协议由调用方判（只认 http/https）。
 */
function withScheme(v) {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `https://${v}`;
}

/**
 * 原始串的 authority 里是不是写了 `:port` 或 `userinfo@`。
 *
 * 不能只靠解析后的 `u.port`：WHATWG URL 会把**默认端口**吃掉（`https://github.com:443/x`
 * 解析出来 `port === ''`），于是「用户明明写了端口」与「没写」在解析结果里长得一模一样。
 * 契约 §3.2 把「端口」明列进拒绝清单，所以这里对补完 scheme 的原始串再查一次 ——
 * 解析后的 `u.port` 检查保留，两层各管一种写法。
 *
 * `[::1]` 这类 IPv6 字面量也会带 `:`，但它们本来就过不了 host 白名单。
 */
function hasExplicitPortOrUserinfo(abs) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(abs);
  if (!m) return false;
  return m[1].includes(':') || m[1].includes('@');
}

/**
 * 酷安用户主页的归一化（契约 §3.1）。
 *
 * 接受的输入：`https://www.coolapk.com/u/123456`、`http://…`（升级成 https）、
 * `www.coolapk.com/u/123456`、`coolapk.com/u/123456`、末尾多一个 `/`。
 *
 * 输出恒为 `https://www.coolapk.com/u/<4-12 位数字>`。
 *
 * 拒绝：非 http/https、其它 host（含 `m.coolapk.com` 这类子域与伪装域）、query、fragment、
 * 端口、userinfo、多段路径（`/u/123/extra`）、`/u/` 之后不是 4–12 位纯数字。
 * 归一不出来返回 `''`，由调用方决定「这算没填」还是「整条拒」。
 */
export function normalizeAuthorCoolapkUrl(raw) {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!v) return '';
  const abs = withScheme(v);
  if (hasExplicitPortOrUserinfo(abs)) return '';
  let u;
  try {
    u = new URL(abs);
  } catch {
    return '';
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
  const host = u.hostname.toLowerCase();
  // 只认这两个：`coolapk.com` 与 `www.coolapk.com`。`m.coolapk.com` 虽然是站内，
  // 但契约把输出钉死在 www，放进来只会多一种「同一张主页的第二种写法」。
  if (host !== 'www.coolapk.com' && host !== 'coolapk.com') return '';
  // 端口/userinfo 已由 hasExplicitPortOrUserinfo 在原始串上拦掉（含默认端口）；这里再查
  // 解析结果，兜住「补 scheme 之后才成形」的怪写法。
  if (u.port || u.username || u.password || u.search || u.hash) return '';
  const segs = u.pathname.split('/').filter((s) => s !== '');
  if (segs.length !== 2 || segs[0] !== 'u') return '';
  if (!UID_RE.test(segs[1])) return '';
  return `https://www.coolapk.com/u/${segs[1]}`;
}

/**
 * GitHub 用户主页的归一化（契约 §3.2）。
 *
 * 接受的输入：`https://github.com/octocat`、`http://…`（升级成 https）、
 * `github.com/octocat`、末尾多一个 `/`。
 *
 * 输出恒为 `https://github.com/<login>`，**login 保留原始大小写**：GitHub 的 login 大小写
 * 不敏感，但索引里显示的是人填的那个字符串，擅自 lower 会让「他填的」与「索引显示的」不一致。
 *
 * 拒绝：`www.github.com`（契约明列）、其它 host、端口、userinfo、query、fragment、
 * 多段路径（仓库地址不是用户主页）、`.git`（login 的字符集本来就不含 `.`）、
 * 不合规的 login（首尾连字符 / 连续 `--` / 超长）、GitHub 的保留路径。
 * 归一不出来返回 `''`，由调用方决定「这算没填」还是「整条拒」。
 */
export function normalizeAuthorGithubUrl(raw) {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!v) return '';
  const abs = withScheme(v);
  if (hasExplicitPortOrUserinfo(abs)) return '';
  let u;
  try {
    u = new URL(abs);
  } catch {
    return '';
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
  // 注意不是 `endsWith('.github.com')`：`www.github.com` 是另一种站，契约要求拒。
  if (u.hostname.toLowerCase() !== 'github.com') return '';
  if (u.port || u.username || u.password || u.search || u.hash) return '';
  const segs = u.pathname.split('/').filter((s) => s !== '');
  if (segs.length !== 1) return '';
  const login = segs[0];
  // 字符集不含 `.`，所以 `octocat.git` 在这里就出局了（契约 §3.2 的 `.git`）。
  if (!GITHUB_LOGIN_RE.test(login)) return '';
  if (login.includes('--')) return '';
  if (GITHUB_RESERVED_LOGINS.has(login.toLowerCase())) return '';
  return `https://github.com/${login}`;
}
