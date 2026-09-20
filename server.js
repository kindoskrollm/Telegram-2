/**
 * tg-proxy — простое зеркало Telegram Web для обхода блокировки.
 *
 * Идея: браузер обращается только к нашему домену (Render).
 * Мы проксируем запросы к *.telegram.org, а в HTML/JS/CSS ответах
 * заменяем прямые ссылки на telegram.org на ссылки вида /x/<домен>/...,
 * которые снова проходят через наш сервер.
 *
 * ВАЖНО (честно предупреждаю): Telegram Web — сложное SPA с service
 * worker'ами и захардкоженными строками внутри минифицированных бандлов.
 * Этот прокси покрывает основные случаи (обычные URL, WebSocket),
 * но не гарантирует 100% работоспособность (звонки, часть медиа,
 * push-уведомления могут не работать). Это отправная точка, а не
 * готовое промышленное решение.
 */

const express = require('express');
const httpProxy = require('http-proxy');
const zlib = require('zlib');

const app = express();
const proxy = httpProxy.createProxyServer({});

// Разрешаем проксировать только поддомены telegram.org — не открываем
// сервер как проиcкивольный публичный прокси на все домены.
const DOMAIN_RE = /^\/x\/([a-z0-9.-]+\.telegram\.org)(\/.*)?$/i;

function isTextType(contentType = '') {
  return /text|javascript|json|css|html|xml/i.test(contentType);
}

app.get('/', (req, res) => {
  res.redirect('/x/web.telegram.org/k/');
});

app.get('/healthz', (req, res) => res.send('ok'));

// Основной прокси для обычных HTTP(S) запросов
app.use((req, res, next) => {
  const m = req.url.match(DOMAIN_RE);
  if (!m) return next();

  const domain = m[1];
  const path = m[2] || '/';
  req.url = path;

  proxy.web(
    req,
    res,
    { target: `https://${domain}`, changeOrigin: true, secure: true },
    (err) => {
      console.error('proxy error:', err.message);
      if (!res.headersSent) res.status(502).send('Proxy error: ' + err.message);
    }
  );
});

app.use((req, res) => res.status(404).send('Not found (ожидался путь вида /x/<domain>/...)'));

// Переписываем текстовые ответы: абсолютные ссылки на telegram.org
// заменяем на относительные пути через наш /x/ прокси.
proxy.on('proxyRes', (proxyRes, req, res) => {
  const contentType = proxyRes.headers['content-type'] || '';

  // Снимаем заголовки, которые могут помешать работе через чужой домен
  delete proxyRes.headers['content-security-policy'];
  delete proxyRes.headers['content-security-policy-report-only'];
  delete proxyRes.headers['strict-transport-security'];
  delete proxyRes.headers['x-frame-options'];

  if (!isTextType(contentType)) {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
    return;
  }

  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('end', () => {
    const raw = Buffer.concat(chunks);
    const encoding = proxyRes.headers['content-encoding'];

    const rewriteAndSend = (bodyBuf) => {
      let text = bodyBuf.toString('utf8');

      // https://xxx.telegram.org  ->  /x/xxx.telegram.org
      text = text.replace(
        /https:\/\/([a-z0-9.-]+\.telegram\.org)/gi,
        (_, domain) => `/x/${domain}`
      );

      // wss://xxx.telegram.org  ->  wss://<наш-домен>/x/xxx.telegram.org
      text = text.replace(/wss:\/\/([a-z0-9.-]+\.telegram\.org)/gi, (_, domain) => {
        const host = req.headers.host;
        return `wss://${host}/x/${domain}`;
      });

      const out = Buffer.from(text, 'utf8');
      const headers = { ...proxyRes.headers };
      delete headers['content-encoding'];
      headers['content-length'] = Buffer.byteLength(out);
      res.writeHead(proxyRes.statusCode, headers);
      res.end(out);
    };

    if (encoding === 'gzip') {
      zlib.gunzip(raw, (err, dec) => rewriteAndSend(err ? raw : dec));
    } else if (encoding === 'br') {
      zlib.brotliDecompress(raw, (err, dec) => rewriteAndSend(err ? raw : dec));
    } else if (encoding === 'deflate') {
      zlib.inflate(raw, (err, dec) => rewriteAndSend(err ? raw : dec));
    } else {
      rewriteAndSend(raw);
    }
  });
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`tg-proxy listening on ${PORT}`);
});

// Проксирование WebSocket-апгрейдов (для реального обмена данными с Telegram)
server.on('upgrade', (req, socket, head) => {
  const m = req.url.match(DOMAIN_RE);
  if (!m) {
    socket.destroy();
    return;
  }
  const domain = m[1];
  const path = m[2] || '/';
  req.url = path;

  proxy.ws(
    req,
    socket,
    head,
    { target: `https://${domain}`, changeOrigin: true, secure: true, ws: true },
    (err) => {
      console.error('ws proxy error:', err.message);
      socket.destroy();
    }
  );
});
