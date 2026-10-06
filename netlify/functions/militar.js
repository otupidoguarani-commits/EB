// Netlify Function: militar.js
// Consulta de militares usando Supabase + sessão segura do EB.

const crypto = require('crypto');

const COOKIE_NAME = 'eb_session';

const RANKS = [
  { nome: 'Recruta', sigla: 'REC', ordem: 1, dias: 0 },
  { nome: 'Soldado', sigla: 'SD', ordem: 2, dias: 1 },
  { nome: 'Cabo', sigla: 'CB', ordem: 3, dias: 1 },
  { nome: 'Terceiro Sargento', sigla: '3° SGT', ordem: 4, dias: 2 },
  { nome: 'Segundo Sargento', sigla: '2° SGT', ordem: 5, dias: 2 },
  { nome: 'Primeiro Sargento', sigla: '1° SGT', ordem: 6, dias: 3 },
  { nome: 'Subtenente', sigla: 'ST', ordem: 7, dias: 3 },
  { nome: 'Aspirante a Oficial', sigla: 'ASP', ordem: 8, dias: 3 },
  { nome: 'Segundo Tenente', sigla: '2° TEN', ordem: 9, dias: 3 },
  { nome: 'Primeiro Tenente', sigla: '1° TEN', ordem: 10, dias: 4 },
  { nome: 'Capitão', sigla: 'CAP', ordem: 11, dias: 4 },
  { nome: 'Major', sigla: 'MAJ', ordem: 12, dias: 4 },
  { nome: 'Tenente Coronel', sigla: 'TEN-CEL', ordem: 13, dias: 5 },
  { nome: 'Coronel', sigla: 'CEL', ordem: 14, dias: 5 },
  { nome: 'General de Brigada', sigla: 'GEN BDA', ordem: 15, dias: 6 },
  { nome: 'General de Divisão', sigla: 'GEN DV', ordem: 16, dias: 7 },
  { nome: 'General de Exército', sigla: 'GEN EX', ordem: 17, dias: 8 },
  { nome: 'Elite Militar', sigla: 'EM', ordem: 18, dias: 10 },
  { nome: 'Elite Secreta', sigla: 'ES', ordem: 19, dias: 12 },
  { nome: 'Elite Real', sigla: 'ER', ordem: 20, dias: 14 }
];

function env(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Variável de ambiente ausente: ${name}`);
  }

  return value;
}

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    },
    body: JSON.stringify(body)
  };
}

function getCookies(event) {
  const header =
    event.headers?.cookie ||
    event.headers?.Cookie ||
    '';

  const cookies = {};

  header.split(';').forEach(part => {
    const index = part.indexOf('=');

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = value;
  });

  return cookies;
}

function keyFromSecret(secret) {
  return crypto
    .createHash('sha256')
    .update(secret)
    .digest();
}

function decryptSession(value, secret) {
  const decoded = decodeURIComponent(value);

  const parts = decoded.split('.');

  if (parts.length !== 3) {
    throw new Error('Sessão inválida.');
  }

  const iv = Buffer.from(parts[0], 'base64url');
  const tag = Buffer.from(parts[1], 'base64url');
  const encrypted = Buffer.from(parts[2], 'base64url');

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    keyFromSecret(secret),
    iv
  );

  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  const session = JSON.parse(
    decrypted.toString('utf8')
  );

  if (!session.exp || Date.now() > session.exp) {
    throw new Error('Sessão expirada.');
  }

  return session;
}

function getSession(event) {
  const cookies = getCookies(event);

  const value = cookies[COOKIE_NAME];

  if (!value) {
    return null;
  }

  try {
    return decryptSession(
      value,
      env('DISCORD_CLIENT_SECRET')
    );
  } catch {
    return null;
  }
}

function getRank(patente) {
  return RANKS.find(
    rank =>
      rank.nome === patente ||
      rank.sigla === patente
  );
}

async function supabaseRequest(path) {
  const url =
    `${env('SUPABASE_URL')}/rest/v1/${path}`;

  const response = await fetch(url, {
    headers: {
      apikey: env('SUPABASE_SECRET_KEY'),
      Authorization:
        `Bearer ${env('SUPABASE_SECRET_KEY')}`,
      'Content-Type': 'application/json'
    }
  });

  const text = await response.text();

  let data;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.error ||
      `Supabase HTTP ${response.status}`
    );
  }

  return data;
}

function calcularCdp(dataPromocao, diasNecessarios) {
  if (!dataPromocao || diasNecessarios <= 0) {
    return {
      completo: true,
      restanteMs: 0
    };
  }

  const inicio =
    new Date(dataPromocao).getTime();

  const prazo =
    diasNecessarios *
    24 *
    60 *
    60 *
    1000;

  const restante =
    Math.max(
      0,
      inicio + prazo - Date.now()
    );

  return {
    completo: restante <= 0,
    restanteMs: restante
  };
}

exports.handler = async event => {
  try {
    const method =
      (event.httpMethod || 'GET').toUpperCase();

    if (method !== 'GET') {
      return json(405, {
        erro: 'Método não permitido.'
      });
    }

    const session = getSession(event);

    if (!session) {
      return json(401, {
        erro: 'Você precisa estar autenticado com o Discord.'
      });
    }

    const identificador =
      event.queryStringParameters?.identificador
        ?.trim();

    if (!identificador) {
      return json(400, {
        erro: 'Identificador do militar não informado.'
      });
    }

    const termo =
      identificador.replace(/,/g, '');

    const filtro =
      `or=(nome.ilike.*${termo}*,roblox_id.eq.${termo},discord_id.eq.${termo})`;

    const militares =
      await supabaseRequest(
        `militares?select=*&${filtro}&limit=1`
      );

    if (!Array.isArray(militares) || !militares.length) {
      return json(404, {
        erro: 'Militar não encontrado.'
      });
    }

    const militar = militares[0];

    const rank =
      getRank(militar.patente);

    if (!rank) {
      return json(200, {
        militar,
        proximaPatente: null,
        cdp: {
          completo: false,
          restanteMs: 0
        }
      });
    }

    const indice =
      RANKS.findIndex(
        item => item.ordem === rank.ordem
      );

    const proxima =
      RANKS[indice + 1] || null;

    const cdp =
      calcularCdp(
        militar.data_promocao,
        rank.dias
      );

    return json(200, {
      militar: {
        id: militar.id,
        discord_id: militar.discord_id,
        nome: militar.nome,
        roblox_id: militar.roblox_id,
        patente: militar.patente,
        data_promocao: militar.data_promocao,
        criado_em: militar.criado_em,
        atualizado_em: militar.atualizado_em
      },

      proximaPatente: proxima
        ? {
            nome: proxima.nome,
            sigla: proxima.sigla,
            diasNecessarios: proxima.dias
          }
        : null,

      cdp: {
        diasNecessarios: rank.dias,
        completo: cdp.completo,
        restanteMs: cdp.restanteMs
      }
    });

 } catch (error) {
    console.error('militar.js:', error);

    return json(500, {
      erro: 'Erro interno ao consultar o militar.',
      detalhe: error.message
    });
}
