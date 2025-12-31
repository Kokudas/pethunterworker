export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === "/health") return new Response("ok", { status: 200 });
    if (url.pathname === "/alarm") return handleAlarm(req, env);
    if (url.pathname === "/interactions") return handleInteractions(req, env);

    return new Response("Not found", { status: 404 });
  },
};

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,X-Client-Key",
  };
}
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function getAllowedGuildSet(env) {
  // 1) 멀티 서버: ALLOWED_GUILDS(쉼표) 우선
  const raw = String(env.ALLOWED_GUILDS || "").trim();
  if (raw) {
    return new Set(
      raw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    );
  }

  // 2) 레거시 호환: 기존 GUILD_ID가 있으면 그 1개만 허용
  const legacy = String(env.GUILD_ID || "").trim();
  if (legacy) return new Set([legacy]);

  // 3) 둘 다 없으면 아무 서버도 허용 안 함(안전)
  return new Set();
}

function isAllowedGuild(env, guildId) {
  const set = getAllowedGuildSet(env);
  return set.size > 0 && set.has(String(guildId));
}

async function getGuildChannelId(env, guildId) {
  // 서버별 설정 우선
  const cfgRaw = await env.SA_KV.get(`guildcfg:${guildId}`);
  if (cfgRaw) {
    try {
      const cfg = JSON.parse(cfgRaw);
      if (cfg?.channelId) return String(cfg.channelId);
    } catch {}
  }

  // fallback: DEFAULT_CHANNEL_ID -> CHANNEL_ID (레거시)
  const fallback =
    String(env.DEFAULT_CHANNEL_ID || "").trim() ||
    String(env.CHANNEL_ID || "").trim();
  return fallback || "";
}

function hasManageGuildOrAdmin(interaction) {
  // interaction.member.permissions: string bitfield
  const permsStr = interaction?.member?.permissions;
  if (!permsStr) return false;

  const perms = BigInt(permsStr);
  const ADMINISTRATOR = 0x8n;
  const MANAGE_GUILD = 0x20n;

  return (perms & ADMINISTRATOR) === ADMINISTRATOR || (perms & MANAGE_GUILD) === MANAGE_GUILD;
}

/* -------------------- /alarm -------------------- */
async function handleAlarm(req, env) {
  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: cors() });
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: cors() });

  const clientKey = req.headers.get("X-Client-Key") || "";
  if (!clientKey) return new Response("Missing X-Client-Key", { status: 401, headers: cors() });

  const keyInfoRaw = await env.SA_KV.get(`key:${clientKey}`);
  if (!keyInfoRaw) return new Response("Invalid key", { status: 401, headers: cors() });

  const keyInfo = JSON.parse(keyInfoRaw); // { userId, ign, guildId, createdAt }
  const body = await req.json().catch(() => ({}));

/* -------------------- /alarm -------------------- */
async function handleAlarm(req, env) {
  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: cors() });
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: cors() });

  const clientKey = req.headers.get("X-Client-Key") || "";
  if (!clientKey) return new Response("Missing X-Client-Key", { status: 401, headers: cors() });

  const keyInfoRaw = await env.SA_KV.get(`key:${clientKey}`);
  if (!keyInfoRaw) return new Response("Invalid key", { status: 401, headers: cors() });

  const keyInfo = JSON.parse(keyInfoRaw); // { userId, ign, guildId, createdAt }
  const body = await req.json().catch(() => ({}));

  const event = String(body.event || "").trim();
  // 지원 이벤트: bag_full, catch_success
  if (event !== "bag_full" && event !== "catch_success") {
    return new Response("Ignored", { status: 204, headers: cors() });
  }

  // 허용 서버 체크 (키가 특정 guildId에 묶여있음)
  if (!isAllowedGuild(env, keyInfo.guildId)) {
    return json({ ok: false, reason: "guild_not_allowed" }, 200, cors());
  }

  // 이벤트별 쿨다운 (서로 방해하지 않게 분리)
  const now = Date.now();
  const cooldownKey = `cooldown:${event}:${clientKey}`;
  const lastRaw = await env.SA_KV.get(cooldownKey);
  const last = lastRaw ? Number(lastRaw) : 0;
  if (now - last < 60_000) return new Response("Cooldown", { status: 204, headers: cors() });

  await env.SA_KV.put(cooldownKey, String(now), { expirationTtl: 120 });

  const channelId = await getGuildChannelId(env, keyInfo.guildId);
  if (!channelId) return json({ ok: false, reason: "channel_not_configured" }, 200, cors());

  const mention = `<@${keyInfo.userId}>`;
  const ign = keyInfo.ign || body.ign || "알수없음";
  const file = body.file ? ` (파일: ${body.file})` : "";

  let content = "";

  if (event === "bag_full") {
    content = `${mention} ⚠️ **가방 [0]칸 감지!** (인게임: ${ign})${file}`;
  } else {
    // catch_success
    // body.nick: 로그에 찍힌 플레이어 닉(예: "사탄")
    // body.pet:  "푸푸"
    // body.plus: 1~4 등(없을 수 있음)
    // body.grade: "seok" | "above"
    const hunter = (body.nick || ign || "알수없음").toString();
    const pet = (body.pet || "").toString();
    const plusNum = Number(body.plus);
    const plusTxt = Number.isFinite(plusNum) ? ` +${plusNum}` : "";
    const gradeTxt = body.grade === "above" ? "정석 이상" : "정석";

    // 메시지는 취향대로 더 짧게/길게 바꿔도 됨
    content =
      `${mention} 🎉 **정석 포획!** ` +
      `(등급: ${gradeTxt}, 펫: ${pet}${plusTxt}, 플레이어: ${hunter}, 연동닉: ${ign})${file}`;
  }

  const r = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content }),
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    return json({ ok: false, status: r.status, detail: t.slice(0, 200) }, 200, cors());
  }

  return json({ ok: true, channelId, event }, 200, cors());
}


  // 허용 서버 체크 (키가 특정 guildId에 묶여있음)
  if (!isAllowedGuild(env, keyInfo.guildId)) {
    return json({ ok: false, reason: "guild_not_allowed" }, 200, cors());
  }

  // 서버측 쿨다운(기본 60초)
  const now = Date.now();
  const lastRaw = await env.SA_KV.get(`cooldown:${clientKey}`);
  const last = lastRaw ? Number(lastRaw) : 0;
  if (now - last < 60_000) return new Response("Cooldown", { status: 204, headers: cors() });

  await env.SA_KV.put(`cooldown:${clientKey}`, String(now), { expirationTtl: 120 });

  const channelId = await getGuildChannelId(env, keyInfo.guildId);
  if (!channelId) return json({ ok: false, reason: "channel_not_configured" }, 200, cors());

  const mention = `<@${keyInfo.userId}>`;
  const ign = keyInfo.ign || body.ign || "알수없음";
  const file = body.file ? ` (파일: ${body.file})` : "";
  const content = `${mention} ⚠️ **가방 [0]칸 감지!** (인게임: ${ign})${file}`;

  const r = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content }),
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    return json({ ok: false, status: r.status, detail: t.slice(0, 200) }, 200, cors());
  }

  return json({ ok: true, channelId }, 200, cors());
}

/* -------------------- /interactions -------------------- */
async function handleInteractions(req, env) {
  const ok = await verifyDiscordRequest(req, env);
  if (!ok) return new Response("Invalid signature", { status: 401 });

  const interaction = await req.json();

  // Ping -> Pong
  if (interaction.type === 1) return json({ type: 1 });

  // Commands only in guild
  const guildId = interaction.guild_id;
  if (!guildId) {
    return json({ type: 4, data: { flags: 64, content: "서버에서만 사용할 수 있어요(DM 불가)." } });
  }

  // Allowlist 체크
  if (!isAllowedGuild(env, guildId)) {
    return json({ type: 4, data: { flags: 64, content: "허용되지 않은 서버입니다." } });
  }

  if (interaction.type === 2) {
    const name = interaction.data?.name;
    const userId = interaction.member?.user?.id || interaction.user?.id;

    if (name === "link") {
      const ign = (interaction.data?.options?.find((o) => o.name === "ign")?.value || "").trim();
      if (!ign) return json({ type: 4, data: { content: "ign(인게임 닉)을 넣어줘!", flags: 64 } });

      const clientKey = makeClientKey();
      const keyInfo = { userId, ign, guildId, createdAt: Date.now() };

      await env.SA_KV.put(`key:${clientKey}`, JSON.stringify(keyInfo));
      await env.SA_KV.put(`user:${guildId}:${userId}`, clientKey);

      return json({
        type: 4,
        data: {
          flags: 64,
          content:
            `✅ 연동 완료!\n` +
            `- 서버: ${guildId}\n` +
            `- 인게임 닉: **${ign}**\n` +
            `- 웹페이지 연동키:\n` +
            `\`${clientKey}\`\n\n` +
            `※ 이 키는 절대 공유하지 마세요.`,
        },
      });
    }

    if (name === "unlink") {
      const oldKey = await env.SA_KV.get(`user:${guildId}:${userId}`);
      if (oldKey) {
// 레거시 + 신규 쿨다운 키 정리
await env.SA_KV.delete(`cooldown:${oldKey}`);
await env.SA_KV.delete(`cooldown:bag_full:${oldKey}`);
await env.SA_KV.delete(`cooldown:catch_success:${oldKey}`);

        await env.SA_KV.delete(`cooldown:${oldKey}`);
        await env.SA_KV.delete(`user:${guildId}:${userId}`);
      }
      return json({ type: 4, data: { flags: 64, content: "🧹 연동 해제 완료!" } });
    }

    if (name === "setchannel") {
      if (!hasManageGuildOrAdmin(interaction)) {
        return json({ type: 4, data: { flags: 64, content: "서버 관리 권한이 필요해요." } });
      }
      const ch = interaction.data?.options?.find((o) => o.name === "channel")?.value;
      if (!ch) return json({ type: 4, data: { flags: 64, content: "channel 옵션이 필요해요." } });

      await env.SA_KV.put(`guildcfg:${guildId}`, JSON.stringify({ channelId: String(ch) }));
      return json({
        type: 4,
        data: { flags: 64, content: `✅ 이 서버 알림 채널을 <#${ch}> 로 설정했어요.` },
      });
    }

    if (name === "showconfig") {
      const ch = await getGuildChannelId(env, guildId);
      const msg = ch
        ? `이 서버 알림 채널: <#${ch}> (guild_id=${guildId})`
        : `이 서버는 알림 채널이 설정되지 않았어요. (/setchannel 사용)`;
      return json({ type: 4, data: { flags: 64, content: msg } });
    }

    return json({ type: 4, data: { flags: 64, content: "알 수 없는 명령이에요." } });
  }

  return json({ type: 4, data: { flags: 64, content: "지원하지 않는 타입" } });
}

/* -------- Discord signature verify (Ed25519) -------- */
async function verifyDiscordRequest(req, env) {
  const signatureHex = req.headers.get("x-signature-ed25519");
  const timestamp = req.headers.get("x-signature-timestamp");
  if (!signatureHex || !timestamp) return false;

  const body = await req.clone().arrayBuffer();

  const tsBytes = new TextEncoder().encode(timestamp);
  const bodyBytes = new Uint8Array(body);

  const message = new Uint8Array(tsBytes.length + bodyBytes.length);
  message.set(tsBytes, 0);
  message.set(bodyBytes, tsBytes.length);

  const publicKeyBytes = hexToBytes(env.DISCORD_PUBLIC_KEY);
  const signatureBytes = hexToBytes(signatureHex);

  const key = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes,
    { name: "NODE-ED25519", namedCurve: "NODE-ED25519" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify({ name: "NODE-ED25519" }, key, signatureBytes, message);
}

function hexToBytes(hex) {
  const clean = String(hex || "").trim().toLowerCase();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function makeClientKey() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}
function base64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

