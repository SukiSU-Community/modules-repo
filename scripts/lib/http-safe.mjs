/**
 * http-safe.mjs
 *
 * 自动更新脚本唯一的网络入口 —— 把「一个外部 URL」变成「一堆字节」，并在中间挡掉 SSRF。
 *
 * 为什么需要它。自动更新会去取三种**外部可控**的地址：模块 `module.prop` 里的
 * `updateJson=`、updateJson 里的 `zipUrl`、以及仓库证据用的 `checksums.txt`。这些东西的
 * 作者是投稿者，不是我们；如果照单全收地 fetch，等于让 CI runner 替别人发内网请求
 * （云元数据 `169.254.169.254`、本机服务、公司内网），而且一次 302 就能把「只信任
 * github.com」的白名单绕干净。所以这里不提供「任意 URL 的通道」，只提供一条有形状的路：
 *
 *   1. 只允许 https，URL 里不许带 userinfo（`https://github.com@evil.tld/` 这种写法在
 *      解析层面就挡掉）；
 *   2. 拒绝 IP 字面量与 localhost / *.local / *.internal 这类名字；
 *   3. `dns.lookup` 之后**每一个**地址都必须是公网 —— 不只看第一个，避免 A 记录混进内网；
 *   4. 重定向自己跟，最多 3 跳，每一跳重新走 1~3（绝不让底层自动 follow）；
 *   5. 连接时把已校验的地址 pin 进 `lookup`，堵住「校验时解析到公网、连接时解析到内网」的
 *      DNS rebinding；
 *   6. 有字节上限（JSON 1MiB / zip 64MiB）与超时（15s），超了直接销毁请求而不是先读完再拒。
 *
 * 为什么不用全局 fetch：Node 的 fetch 不给你换 lookup 的口子，也没法在流式读取时按字节数
 * 精确中止；而这里要做的事（pin 地址 + 流式限额）正是 fetch 不暴露的两件事。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */
import dns from 'node:dns';
import https from 'node:https';
import net from 'node:net';

export const DEFAULT_TIMEOUT_MS = 15_000;
export const MAX_REDIRECTS = 3;
export const MAX_JSON_BYTES = 1024 * 1024;
export const MAX_ZIP_BYTES = 64 * 1024 * 1024;

/** 这些状态码算重定向；其余原样交给调用方判。 */
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/** 带类型的错误：调用方靠 code 区分「拒绝这个地址」与「网络确实坏了」。 */
export class SafeHttpError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'SafeHttpError';
    this.code = code;
    Object.assign(this, extra);
  }
}

// ── IP 字面量判定 ──────────────────────────────────────────────────────────

/** IPv4 文本转 32 位无符号数（调用前已确认是合法 IPv4）。 */
function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return (((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0);
}

function inIpv4Prefix(n, base, bits) {
  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
  return ((n & mask) >>> 0) === ((base & mask) >>> 0);
}

/**
 * IPv6 文本转 16 字节。返回 null 表示不是合法 IPv6。
 *
 * 自己写而不是靠字符串前缀匹配：`fe80::1`、`FE80:0:0:0:0:0:0:1`、`fe80::1%eth0` 是同一个
 * 地址的三种写法，字符串判据在这里一定会漏。实现覆盖 `::` 压缩与末尾内嵌 IPv4。
 */
export function parseIpv6(ip) {
  let s = String(ip || '').trim().toLowerCase();
  if (!s) return null;
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone); // fe80::1%eth0 的 scope id 不参与前缀比较
  if (!net.isIPv6(s)) return null;

  let tail = [];
  const v4 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (v4) {
    const parts = v4[1].split('.').map(Number);
    if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    tail = [(parts[0] << 8) | parts[1], (parts[2] << 8) | parts[3]];
    s = s.slice(0, s.length - v4[1].length);
    if (s.endsWith(':')) s = s.slice(0, -1);
  }
  // 去掉末尾 IPv4 后可能出现 `::`（如 `::` + 空），交给下面按 `::` 切分。
  if (s === '') s = '::';

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const groupsOf = (part) => (part === '' ? [] : part.split(':').map((h) => {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return NaN;
    return parseInt(h, 16);
  }));
  const head = groupsOf(halves[0]);
  const rest = halves.length === 2 ? groupsOf(halves[1]) : [];
  if ([...head, ...rest].some((n) => Number.isNaN(n))) return null;
  const explicit = head.length + rest.length + tail.length;
  if (halves.length === 1) {
    if (explicit !== 8) return null;
  } else if (explicit > 8) {
    return null;
  }
  const groups = halves.length === 1
    ? [...head, ...tail]
    : [...head, ...new Array(8 - explicit).fill(0), ...rest, ...tail];
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  groups.forEach((g, i) => {
    bytes[i * 2] = g >> 8;
    bytes[i * 2 + 1] = g & 0xff;
  });
  return bytes;
}

function ipv6InPrefix(bytes, prefix, bits) {
  if (!bytes || !prefix) return false;
  const full = Math.floor(bits / 8);
  const rem = bits % 8;
  for (let i = 0; i < full; i += 1) if (bytes[i] !== prefix[i]) return false;
  if (rem) {
    const mask = (0xff << (8 - rem)) & 0xff;
    if ((bytes[full] & mask) !== (prefix[full] & mask)) return false;
  }
  return true;
}

/**
 * 非公网 IPv4 段。除了大家熟知的 10/8、172.16/12、192.168/16、127/8、169.254/16，还挡
 * 掉文档/基准测试段（192.0.2/24 等）与保留段：它们不会出现在真实外网服务上，放行只会
 * 变成一类探测内网拓扑的探针。
 */
const IPV4_BLOCKED = [
  ['0.0.0.0', 8],        // 本网络
  ['10.0.0.0', 8],       // 私网 A
  ['100.64.0.0', 10],    // 运营商级 NAT
  ['127.0.0.0', 8],      // 回环
  ['169.254.0.0', 16],   // 链路本地（云元数据常在这）
  ['172.16.0.0', 12],    // 私网 B
  ['192.0.0.0', 24],     // IETF 协议分配
  ['192.0.2.0', 24],     // 文档 TEST-NET-1
  ['192.88.99.0', 24],   // 6to4 中继
  ['192.168.0.0', 16],   // 私网 C
  ['198.18.0.0', 15],    // 基准测试
  ['198.51.100.0', 24],  // 文档 TEST-NET-2
  ['203.0.113.0', 24],   // 文档 TEST-NET-3
  ['224.0.0.0', 4],      // 组播
  ['240.0.0.0', 4],      // 保留
  ['255.255.255.255', 32],
];

/**
 * 非公网 IPv6 段。`::ffff:0:0/96` 整段拒绝：IPv4-mapped 地址会把内网地址夹带进来，而真实
 * 外网 DNS 不会以这种形式返回 A 记录，拒掉它不影响任何正常取数。
 */
const IPV6_BLOCKED = [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],       // 唯一本地地址
  ['fe80::', 10],      // 链路本地
  ['ff00::', 8],       // 组播
  ['2001:db8::', 32],  // 文档
  ['64:ff9b::', 96],   // NAT64
  ['2002::', 16],      // 6to4（内嵌 IPv4）
  ['100::', 64],       // 丢弃
  ['::ffff:0:0', 96],  // IPv4-mapped
  ['2001::', 32],      // Teredo
];

/** 一个地址字符串是不是「公网」地址。非法/解析不了的一律 false（fail closed）。 */
export function isPublicIp(ip) {
  const s = String(ip || '').trim();
  if (!s) return false;
  if (net.isIPv4(s)) {
    const n = ipv4ToInt(s);
    return !IPV4_BLOCKED.some(([base, bits]) => inIpv4Prefix(n, ipv4ToInt(base), bits));
  }
  const v6 = parseIpv6(s);
  if (!v6) return false;
  return !IPV6_BLOCKED.some(([prefix, bits]) => ipv6InPrefix(v6, parseIpv6(prefix), bits));
}

/**
 * 主机名层面的拒绝。IP 字面量一律拒 —— 契约要求「只认主机名」，而解析器拿到 IP 字面量
 * 时根本不会走 dns.lookup，第 3 道检查就形同虚设。
 */
export function isBlockedHostname(hostname) {
  let h = String(hostname || '').trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (!h) return true;
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (net.isIP(h)) return true;
  return h === 'localhost'
    || h.endsWith('.localhost')
    || h.endsWith('.local')
    || h.endsWith('.internal')
    || h.endsWith('.home.arpa');
}

/** URL 形状校验（DNS 之前就能判的那部分）。返回 URL 对象，不合法则抛 SafeHttpError。 */
export function assertAllowedUrl(raw) {
  let u;
  try {
    u = new URL(String(raw));
  } catch {
    throw new SafeHttpError('bad-url', `不是合法的 URL：${String(raw).slice(0, 200)}`);
  }
  if (u.protocol !== 'https:') {
    throw new SafeHttpError('bad-protocol', `只允许 https：${u.href}`);
  }
  if (u.username || u.password) {
    throw new SafeHttpError('bad-url', `URL 里不允许带凭据：${u.href}`);
  }
  if (!u.hostname) {
    throw new SafeHttpError('bad-url', `URL 没有主机名：${u.href}`);
  }
  if (isBlockedHostname(u.hostname)) {
    throw new SafeHttpError('blocked-host', `拒绝的主机：${u.hostname}`);
  }
  return u;
}

// ── 取数客户端 ────────────────────────────────────────────────────────────

/**
 * 生成一个带校验/重定向/限额的取数客户端。
 *
 * 所有外部依赖都可注入，单测因此不需要联网：
 *   - `lookupImpl(host, { all: true })` → [{ address, family }]（默认 node:dns 的 promises 版）
 *   - `requestImpl(options)` → { status, headers, body }（默认走 https.request）
 *   - `now()`：只用于将来可能的超时预算，当前保留
 */
export function createSafeHttp({
  lookupImpl = dns.promises.lookup,
  requestImpl = defaultRequest,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxRedirects = MAX_REDIRECTS,
  now = Date.now,
} = {}) {
  /** host -> 地址数组 | SafeHttpError。一次运行内复用；失败也缓存，避免同一坏域名反复解析。 */
  const dnsCache = new Map();

  async function resolvePublicAddresses(hostname) {
    const key = hostname.toLowerCase();
    const cached = dnsCache.get(key);
    if (cached instanceof Error) throw cached;
    if (cached) return cached;

    let raw;
    try {
      raw = await lookupImpl(key, { all: true });
    } catch (err) {
      const e = new SafeHttpError('dns-failed', `域名解析失败：${key}（${err && err.message ? err.message : err}）`);
      dnsCache.set(key, e);
      throw e;
    }
    const list = (Array.isArray(raw) ? raw : [raw])
      .filter((a) => a && typeof a.address === 'string' && a.address)
      .map((a) => ({ address: a.address, family: Number(a.family) || net.isIP(a.address) }));
    if (!list.length) {
      const e = new SafeHttpError('dns-failed', `域名没有解析出地址：${key}`);
      dnsCache.set(key, e);
      throw e;
    }
    // 关键：不是「第一个是公网就行」，而是每一个都必须是。混合 A 记录是绕过 DNS 白名单的常见形状。
    const bad = list.find((a) => !isPublicIp(a.address));
    if (bad) {
      const e = new SafeHttpError('blocked-address', `拒绝连接：${key} 解析到非公网地址 ${bad.address}`);
      dnsCache.set(key, e);
      throw e;
    }
    dnsCache.set(key, list);
    return list;
  }

  /** 把已校验地址钉进 lookup：autoSelectFamily 走 all=true 时给出全部公网地址，否则给第一个。 */
  function pinnedLookup(addrs) {
    return (hostname, options, callback) => {
      if (options && options.all) {
        return callback(null, addrs.map((a) => ({ address: a.address, family: a.family })));
      }
      const want = options && (options.family === 4 || options.family === 6) ? Number(options.family) : 0;
      const pick = want ? addrs.find((a) => a.family === want) : addrs[0];
      if (!pick) return callback(new SafeHttpError('dns-failed', `没有 family=${want} 的公网地址：${hostname}`));
      return callback(null, pick.address, pick.family);
    };
  }

  async function request(method, rawUrl, {
    headers = {},
    body = null,
    maxBytes = null,
    timeoutMs: perRequestTimeout = timeoutMs,
  } = {}) {
    let url = assertAllowedUrl(rawUrl);
    let currentMethod = String(method || 'GET').toUpperCase();
    let payload = body;
    let currentHeaders = { ...headers };

    for (let hop = 0; ; hop += 1) {
      const addrs = await resolvePublicAddresses(url.hostname);
      const res = await requestImpl({
        method: currentMethod,
        url: url.href,
        headers: currentHeaders,
        body: payload,
        maxBytes,
        timeoutMs: perRequestTimeout,
        lookup: pinnedLookup(addrs),
      });
      if (!res || typeof res.status !== 'number') {
        throw new SafeHttpError('bad-response', `HTTP 响应形状不对：${url.href}`);
      }
      // 注入的 requestImpl 可能已经读完整个响应，所以在这一层再判一次上限，
      // 让「换成别的传输实现」也逃不掉限额。
      if (res.body && maxBytes && res.body.length > maxBytes) {
        throw new SafeHttpError('too-large', `响应超过 ${maxBytes} 字节上限：${url.href}`, { limit: maxBytes });
      }

      const location = res.headers && (res.headers.location || res.headers.Location);
      if (REDIRECT_STATUS.has(res.status) && location) {
        if (hop >= maxRedirects) {
          throw new SafeHttpError('too-many-redirects', `重定向超过 ${maxRedirects} 次：${url.href}`);
        }
        // 逐跳重新做「形状 + DNS + 公网」三件事，绝不复用上一跳的结论。
        let nextUrl;
        try {
          nextUrl = new URL(String(location), url).href;
        } catch {
          throw new SafeHttpError('bad-url', `重定向地址不合法：${String(location).slice(0, 200)}`);
        }
        url = assertAllowedUrl(nextUrl);
        const switchToGet = res.status === 303
          || ((res.status === 301 || res.status === 302) && currentMethod !== 'GET' && currentMethod !== 'HEAD');
        if (switchToGet) {
          currentMethod = 'GET';
          payload = null;
          currentHeaders = dropBodyHeaders(currentHeaders);
        }
        continue;
      }
      return { status: res.status, headers: res.headers || {}, body: res.body || Buffer.alloc(0), url: url.href };
    }
  }

  async function getBuffer(url, options = {}) {
    return request('GET', url, {
      ...options,
      maxBytes: options.maxBytes ?? MAX_ZIP_BYTES,
    });
  }

  async function getText(url, options = {}) {
    const res = await request('GET', url, {
      ...options,
      maxBytes: options.maxBytes ?? MAX_JSON_BYTES,
    });
    return { ...res, text: res.body.toString('utf8') };
  }

  async function getJson(url, options = {}) {
    const res = await request('GET', url, {
      ...options,
      maxBytes: options.maxBytes ?? MAX_JSON_BYTES,
    });
    let json = null;
    try {
      json = JSON.parse(res.body.toString('utf8'));
    } catch {
      // 非 200 的正文不可解析时**不在这里抛**：调用方要先按状态码判「作者侧 404（拒模块）」
      // 还是「上游 5xx（整轮红）」。若在这里抛 bad-json，5xx 的 HTML 错误页会被误判成
      // 「作者给了坏 JSON」，于是该红的 run 悄悄变成了「拒绝一个模块」。
      if (res.status === 200) {
        throw new SafeHttpError('bad-json', `响应不是合法 JSON：${url}`, { status: res.status });
      }
    }
    return { ...res, json };
  }

  async function postJson(url, value, options = {}) {
    const payload = Buffer.from(JSON.stringify(value));
    const headers = {
      'content-type': 'application/json',
      'content-length': String(payload.length),
      ...(options.headers || {}),
    };
    const res = await request('POST', url, { ...options, headers, body: payload });
    let json = null;
    try {
      json = res.body.length ? JSON.parse(res.body.toString('utf8')) : null;
    } catch {
      json = null;
    }
    return { ...res, json };
  }

  async function postBinary(url, bytes, options = {}) {
    const payload = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const headers = {
      'content-length': String(payload.length),
      ...(options.headers || {}),
    };
    const res = await request('POST', url, { ...options, headers, body: payload });
    let json = null;
    try {
      json = res.body.length ? JSON.parse(res.body.toString('utf8')) : null;
    } catch {
      json = null;
    }
    return { ...res, json };
  }

  return { request, getBuffer, getText, getJson, postJson, postBinary, resolvePublicAddresses, now };
}

function dropBodyHeaders(headers) {
  const out = { ...headers };
  for (const key of Object.keys(out)) {
    if (key.toLowerCase() === 'content-type' || key.toLowerCase() === 'content-length') delete out[key];
  }
  return out;
}

/**
 * 默认传输：https.request + 手动限额。
 *
 * 为什么不透传 `agent`：默认全局 Agent 会复用连接，而「pin 已校验地址」是按连接生效的，
 * 复用等于把上一次的校验结论借给下一次请求。`agent: false` 强制每次新建连接。
 */
function defaultRequest({ method, url, headers, body, maxBytes, timeoutMs, lookup }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const req = https.request({
      protocol: 'https:',
      hostname: u.hostname,
      port: u.port || 443,
      path: `${u.pathname}${u.search}`,
      method,
      headers,
      lookup,
      agent: false,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (maxBytes && size > maxBytes) {
          res.destroy();
          fail(new SafeHttpError('too-large', `响应超过 ${maxBytes} 字节上限：${url}`, { limit: maxBytes }));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (settled) return;
        settled = true;
        resolve({ status: res.statusCode, headers: res.headers || {}, body: Buffer.concat(chunks) });
      });
      res.on('error', (err) => fail(wrapNetworkError(err, url)));
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new SafeHttpError('timeout', `请求超时（${timeoutMs}ms）：${url}`));
    });
    req.on('error', (err) => fail(err instanceof SafeHttpError ? err : wrapNetworkError(err, url)));
    if (body) req.write(body);
    req.end();
  });
}

function wrapNetworkError(err, url) {
  const code = err && err.code ? err.code : '';
  return new SafeHttpError('network', `网络错误：${url}${code ? `（${code}）` : ''}`, { cause: code });
}
