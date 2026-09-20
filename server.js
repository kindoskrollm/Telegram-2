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
  let aborted = false;
  res.on('close', () => { aborted = true; });
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('end', () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks);
    const encoding = proxyRes.headers['content-encoding'];

    const rewriteAndSend = (bodyBuf) => {
      // Клиент мог уже отключиться, или ответ уже был отправлен раньше —
      // тогда просто ничего не делаем, вместо падения с ERR_HTTP_HEADERS_SENT.
      if (res.headersSent || res.writableEnded) return;

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

      // Для HTML дополнительно внедряем перехватчик fetch/WebSocket/XHR.
      // Это нужно, потому что часть адресов Telegram Web собирает
      // на лету (например "dc" + номер + ".web.telegram.org"), а не
      // пишет готовой строкой — такие случаи текстовая замена выше
      // не ловит. Перехватчик подменяет вызовы уже в момент их
      // выполнения, независимо от того, как был собран URL.
      if (/text\/html/i.test(contentType)) {
        const injector = `<script>(function(){
  var HOST = location.host;
  function rewrite(url){
    try {
      var u = new URL(url, location.href);
      if (/\\.telegram\\.org$/i.test(u.hostname)) {
        var proto = (u.protocol === 'wss:' || u.protocol === 'ws:') ? 'wss:' : 'https:';
        return proto + '//' + HOST + '/x/' + u.hostname + u.pathname + u.search;
      }
    } catch(e) {}
    return url;
  }
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function(input, init){
      if (typeof input === 'string') input = rewrite(input);
      else if (input && input.url) input = new Request(rewrite(input.url), input);
      return origFetch.call(this, input, init);
    };
  }
  var OrigWS = window.WebSocket;
  if (OrigWS) {
    var PatchedWS = function(url, protocols){
      return protocols ? new OrigWS(rewrite(url), protocols) : new OrigWS(rewrite(url));
    };
    PatchedWS.prototype = OrigWS.prototype;
    PatchedWS.CONNECTING = OrigWS.CONNECTING;
    PatchedWS.OPEN = OrigWS.OPEN;
    PatchedWS.CLOSING = OrigWS.CLOSING;
    PatchedWS.CLOSED = OrigWS.CLOSED;
    window.WebSocket = PatchedWS;
  }
  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url){
    arguments[1] = rewrite(url);
    return origOpen.apply(this, arguments);
  };
})();</script>`;

        if (/<head[^>]*>/i.test(text)) {
          text = text.replace(/<head[^>]*>/i, (m) => m + injector);
        } else {
          text = injector + text;
        }
      }

      const out = Buffer.from(text, 'utf8');
      const headers = { ...proxyRes.headers };
      delete headers['content-encoding'];
      headers['content-length'] = Buffer.byteLength(out);

      try {
        res.writeHead(proxyRes.statusCode, headers);
        res.end(out);
      } catch (err) {
        // Соединение оборвалось между проверкой выше и записью — просто игнорируем.
      }
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
