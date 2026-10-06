// Netlify Function: auth.js
// Discord OAuth2 + sessão segura + leitura de cargos do servidor.

const crypto = require('crypto');

const COOKIE_NAME = 'eb_session';
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;

const RANKS = [
  { nome: 'Recruta', sigla: 'REC', role: '1549542966945644554', ordem: 1 },
  { nome: 'Soldado', sigla: 'SD', role: '1549541696042176573', ordem: 2 },
  { nome: 'Cabo', sigla: 'CB', role: '1549542964546633839', ordem: 3 },
  { nome: 'Terceiro Sargento', sigla: '3° SGT', role: '1549542961367228438', ordem: 4 },
  { nome: 'Segundo Sargento', sigla: '2° SGT', role: '1549542959211618308', ordem: 5 },
  { nome: 'Primeiro Sargento', sigla: '1° SGT', role: '1549542958838190250', ordem: 6 },
  { nome: 'Subtenente', sigla: 'ST', role: '1549542957361790986', ordem: 7 },
  { nome: 'Aspirante a Oficial', sigla: 'ASP', role: '1549542954983493702', ordem: 8 },
  { nome: 'Segundo Tenente', sigla: '2° TEN', role: '1549542954052362270', ordem: 9 },
  { nome: 'Primeiro Tenente', sigla: '1° TEN', role: '1549542951703810098', ordem: 10 },
  { nome: 'Capitão', sigla: 'CAP', role: '1549542948016881797', ordem: 11 },
  { nome: 'Major', sigla: 'MAJ', role: '1549542945710014475', ordem: 12 },
  { nome: 'Tenente Coronel', sigla: 'TEN-CEL', role: '1549542945017827449', ordem: 13 },
  { nome: 'Coronel', sigla: 'CEL', role: '1549542943763861617', ordem: 14 },
  { nome: 'General de Brigada', sigla: 'GEN BDA', role: '1549542942711095426', ordem: 15 },
  { nome: 'General de Divisão', sigla: 'GEN DV', role: '1549542941691740260', ordem: 16 },
  { nome: 'General de Exército', sigla: 'GEN EX', role: '1549542938630168706', ordem: 17 },
  { nome: 'Elite Militar', sigla: 'EM', role: '1556702628451324067', ordem: 18 },
  { nome: 'Elite Secreta', sigla: 'ES', role: '1556702912070033498', ordem: 19 },
  { nome: 'Elite Real', sigla: 'ER', role: '1556702981812912349', ordem: 20 }
];

function env(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Variável de ambiente ausente: ${name}`);
  }

  return value;
}

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    },
    body: JSON.stringify(body)
  };
}

function keyFromSecret(secret) {
  return crypto
    .createHash('sha256')
    .update(secret)
    .digest();
}

function encryptSession(data, secret) {
  const key = keyFromSecret(secret);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  const plaintext = Buffer.from(
    JSON.stringify(data),
    'utf8'
  );

  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [iv, tag, encrypted]
    .map(b => b.toString('base64url'))
    .join('.');
}

async function discordRequest(path, accessToken) {
  const response = await fetch(
    `https://discord.com/api/v10${path}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'EB-Central-de-Comando/1.0'
      }
    }
  );

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    throw new Error(
      data?.message ||
      `Discord HTTP ${response.status}`
    );
  }

  return data;
}

async function exchangeCode(code, redirectUri) {
  const params = new URLSearchParams();

  params.set(
    'client_id',
    env('DISCORD_CLIENT_ID')
  );

  params.set(
    'client_secret',
    env('DISCORD_CLIENT_SECRET')
  );

  params.set(
    'grant_type',
    'authorization_code'
  );

  params.set('code', code);
  params.set('redirect_uri', redirectUri);

  const response = await fetch(
    'https://discord.com/api/v10/oauth2/token',
    {
      method: 'POST',

      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },

      body: params.toString()
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data?.error_description ||
      'Discord recusou o código OAuth2.'
    );
  }

  return data;
}

function getRankFromRoles(roleIds) {
  const matches = RANKS.filter(rank =>
    roleIds.includes(rank.role)
  );

  if (!matches.length) {
    return null;
  }

  matches.sort(
    (a, b) => b.ordem - a.ordem
  );

  return matches[0];
}

async function getRoblox(discordId) {
  const apiKey =
    process.env.BLOXLINK_API_KEY;

  const guildId =
    env('DISCORD_GUILD_ID');

  if (!apiKey) {
    return null;
  }

  try {
    const response = await fetch(
      `https://api.blox.link/v4/public/guilds/${guildId}/discord-to-roblox/${discordId}`,
      {
        headers: {
          Authorization: apiKey
        }
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json();

    return data?.robloxID
      ? String(data.robloxID)
      : null;

  } catch {
    return null;
  }
}

function sessionCookie(value) {
  return [
    `${COOKIE_NAME}=${encodeURIComponent(value)}`,
    'Path=/',
    `Max-Age=${SESSION_MAX_AGE}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

function clearCookie() {
  return [
    `${COOKIE_NAME}=`,
    'Path=/',
    'Max-Age=0',
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

async function handleLogin(event) {
  let body;

  try {
    body = JSON.parse(
      event.body || '{}'
    );
  } catch {
    return json(400, {
      erro: 'JSON inválido.'
    });
  }

  const code = body.code;
  const redirectUri =
    body.redirect_uri;

  if (!code || !redirectUri) {
    return json(400, {
      erro:
        'Código OAuth2 ou redirect_uri ausente.'
    });
  }

  const expectedRedirect =
    process.env.URL ||
    'https://eb-exercito-brasileiro.netlify.app';

  if (redirectUri !== expectedRedirect) {
    return json(400, {
      erro: 'Redirect URI inválida.'
    });
  }

  const token = await exchangeCode(
    code,
    redirectUri
  );

  const user = await discordRequest(
    '/users/@me',
    token.access_token
  );

  const guildId =
    env('DISCORD_GUILD_ID');

  const member = await discordRequest(
    `/users/@me/guilds/${guildId}/member`,
    token.access_token
  );

  const roleIds =
    Array.isArray(member.roles)
      ? member.roles.map(String)
      : [];

  const rank =
    getRankFromRoles(roleIds);

  const creatorRoleId =
    env('DISCORD_CREATOR_ROLE_ID');

  const isCreator =
    roleIds.includes(
      String(creatorRoleId)
    );

  const chefe =
    (user.username || '').toLowerCase() ===
    (process.env.USUARIO_CHEFE || '').toLowerCase();

  const robloxId =
    await getRoblox(user.id);

  const avatar = user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`
    : 'https://cdn.discordapp.com/embed/avatars/0.png';

  const session = {
    exp:
      Date.now() +
      SESSION_MAX_AGE * 1000,

    access_token:
      token.access_token,

    discord_id:
      user.id,

    username:
      user.username,

    global_name:
      user.global_name ||
      user.username,

    avatar,

    roblox_id:
      robloxId,

    roles:
      roleIds,

    patente:
      rank?.nome || null,

    sigla:
      rank?.sigla || null,

    is_creator:
      isCreator,

    is_chefe:
      chefe
  };

  const encrypted =
    encryptSession(
      session,
      env('DISCORD_CLIENT_SECRET')
    );

  return json(
    200,

    {
      ok: true,

      usuario: {
        idDiscord:
          user.id,

        nome:
          user.global_name ||
          user.username,

        username:
          user.username,

        avatar,

        robloxId,

        patente:
          rank?.nome ||
          'PATENTE NÃO IDENTIFICADA',

        sigla:
          rank?.sigla || null,

        isCreator,

        isChefe:
          chefe
      }
    },

    {
      'Set-Cookie':
        sessionCookie(encrypted)
    }
  );
}

exports.handler = async event => {
  try {
    const method =
      (event.httpMethod || 'GET')
        .toUpperCase();

    if (method === 'POST') {
      return await handleLogin(event);
    }

    if (method === 'DELETE') {
      return json(
        200,
        { ok: true },
        {
          'Set-Cookie':
            clearCookie()
        }
      );
    }

    return json(
      405,
      {
        erro:
          'Método não permitido.'
      }
    );

  } catch (error) {

    console.error(
      'auth.js:',
      error
    );

    return json(
      500,
      {
        erro:
          'Erro interno durante a autenticação.'
      }
    );
  }
};
