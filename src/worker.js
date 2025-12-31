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

/* -------------------- /alarm -------------------- */
/** 웹(정적)에서 [0]칸 감지 시 호출 -> 디스코드 채널로 봇 메시지 전송 */
async function handleAlarm(req, env) {
  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: cors() });
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: cors() });

  const clientKey = req.headers.get("X-Client-Key") || "";
  if (!clientKey) return new Response("Missing X-Client-Key", { status: 401, headers: cors() });

  const keyInfoRaw = await env.SA_KV.get(`key:${clientKey}`);
  if (!keyInfoRaw) return new Response("Invalid key", { status: 401, headers: cors() });

  const keyInfo = JSON.parse(keyInfoRaw); // { userId, ign, guildId, createdAt }
  const body = await req.json().catch(() => ({}));

  if (body.event !== "bag_full") return new Response("Ignored", { status: 204, headers: cors() });

  // 서버측 쿨다운(기본 60초)
  const now = Date.now();
  const lastRaw = await env.SA_KV.get(`cooldown:${clientKey}`);
  const last = lastRaw ? Number(lastRaw) : 0;
  if (now - last < 60_000) return new Response("Cooldown", { status: 204, headers: cors() });

  await env.SA_KV.put(`cooldown:${clientKey}`, String(now), { expirationTtl: 120 });

  const mention = `<@${keyInfo.userId}>`;
  const ign = keyInfo.ign || body.ign || "알수없음";
  const file = body.file ? ` (파일: ${body.file})` : "";
  const content = `${mention} ⚠️ **가방 [0]칸 감지!** (인게임: ${ign})${file}`;

  // 채널 메시지 전송: POST /channels/{channel.id}/messages :contentReference[oaicite:3]{index=3}
  const r = await fetch(`https://discord.com/api/v10/channels/${env.CHANNEL_ID}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`, // 봇 토큰 인증 :contentReference[oaicite:4]{index=4}
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content }),
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    return json({ ok: false, status: r.status, detail: t.slice(0, 200) }, 200, cors());
  }
  return json({ ok: true }, 200, cors());
}

/* -------------------- /interactions -------------------- */
/** Discord 슬래시커맨드용 endpoint */
async function handleInteractions(req, env) {
  const ok = await verifyDiscordRequest(req, env);
  if (!ok) return new Response("Invalid signature", { status: 401 }); // Discord는 서명 검증 실패 시 거부 :contentReference[oaicite:5]{index=5}

  const interaction = await req.json();

  // Discord가 Endpoint URL 등록/상태 확인용으로 PING(type:1)을 보냄 -> PONG(type:1) 응답 :contentReference[oaicite:6]{index=6}
  if (interaction.type === 1) {
    return json({ type: 1 });
  }

  // Application Command
  if (interaction.type === 2) {
    const name = interaction.data?.name;
    const userId = interaction.member?.user?.id || interaction.user?.id;
    const guildId = interaction.guild_id;

const allowedGuild = String(env.GUILD_ID || "").trim();

if (!allowedGuild) {
  return json({
    type: 4,
    data: { flags: 64, content: "설정 오류: Worker에 GUILD_ID가 비어있어요." }
  });
}

if (String(guildId) !== allowedGuild) {
  return json({
    type: 4,
    data: {
      flags: 64,
      content:
        `이 서버에서만 사용 가능해요.\n` +
        `- 현재 guild_id: ${guildId}\n` +
        `- 허용 GUILD_ID: ${allowedGuild}`
    }
  });
}


    if (name === "link") {
      const ign = (interaction.data?.options?.find(o => o.name === "ign")?.value || "").trim();
      if (!ign) return json({ type: 4, data: { content: "ign(인게임 닉)을 넣어줘!", flags: 64 } });

      const clientKey = makeClientKey();
      const keyInfo = { userId, ign, guildId, createdAt: Date.now() };

      await env.SA_KV.put(`key:${clientKey}`, JSON.stringify(keyInfo));
      await env.SA_KV.put(`user:${guildId}:${userId}`, clientKey);

      return json({
        type: 4,
        data: {
          flags: 64, // ephemeral(본인만 보기)
          content:
            `✅ 연동 완료!\n` +
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
        await env.SA_KV.delete(`key:${oldKey}`);
        await env.SA_KV.delete(`cooldown:${oldKey}`);
        await env.SA_KV.delete(`user:${guildId}:${userId}`);
      }
      return json({ type: 4, data: { flags: 64, content: "🧹 연동 해제 완료!" } });
    }

    return json({ type: 4, data: { flags: 64, content: "알 수 없는 명령이에요." } });
  }

  return json({ type: 4, data: { flags: 64, content: "지원하지 않는 타입" } });
}

/** Discord는 x-signature-ed25519 / x-signature-timestamp 헤더로 서명 검증을 요구함 :contentReference[oaicite:7]{index=7} */
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

  // Cloudflare Workers WebCrypto: NODE-ED25519 알고리즘 지원 :contentReference[oaicite:8]{index=8}
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
  const clean = hex.trim().toLowerCase();
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

