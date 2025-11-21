/**
 * AI DLP Proxy - Data Leakage Prevention Proxy for AI Tools
 *
 * This proxy intercepts HTTPS traffic and analyzes it for potential
 * data leakage indicators such as credentials, code, and sensitive data.
 */

const http = require('http');
const net = require('net');
const { URL } = require('url');
const { analyzeContent, shouldBlock } = require('./detector');
const { logRequest, logStartup, logError, logBlocked } = require('./logger');

// Configuration
const config = {
  port: parseInt(process.env.PROXY_PORT) || 8888,
  blockMode: process.env.BLOCK_MODE === 'true', // Set to true to block suspicious requests
  logFullBody: process.env.LOG_FULL_BODY === 'true',
  targetHosts: (process.env.TARGET_HOSTS || '').split(',').filter(Boolean), // Empty = all hosts
};

// Create the proxy server
const server = http.createServer(handleHttpRequest);
server.on('connect', handleConnectRequest);

/**
 * Handle regular HTTP requests (non-CONNECT)
 */
function handleHttpRequest(clientReq, clientRes) {
  const url = clientReq.url;
  const method = clientReq.method;
  const host = clientReq.headers.host;

  let body = '';

  clientReq.on('data', chunk => {
    body += chunk.toString();
  });

  clientReq.on('end', () => {
    // Analyze the request
    const findings = analyzeContent(body, clientReq.headers['content-type']);

    logRequest({
      method,
      url,
      host,
      headers: clientReq.headers,
      body: config.logFullBody ? body : body.substring(0, 1000),
      findings,
    });

    // Block if configured and findings warrant it
    if (config.blockMode && shouldBlock(findings)) {
      logBlocked(url, findings.reasons);
      clientRes.writeHead(403, { 'Content-Type': 'text/plain' });
      clientRes.end('Request blocked by DLP proxy: Sensitive content detected');
      return;
    }

    // Forward the request
    const parsedUrl = new URL(url);
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 80,
      path: parsedUrl.pathname + parsedUrl.search,
      method: method,
      headers: clientReq.headers,
    };

    const proxyReq = http.request(options, (proxyRes) => {
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes);
    });

    proxyReq.on('error', (err) => {
      logError('Proxy request error', err);
      clientRes.writeHead(502);
      clientRes.end('Proxy error');
    });

    if (body) {
      proxyReq.write(body);
    }
    proxyReq.end();
  });
}

/**
 * Handle HTTPS CONNECT requests (tunnel)
 *
 * For HTTPS, we create a tunnel. To inspect the content, you would need
 * to perform TLS interception with a custom CA certificate.
 * This basic version logs the connection metadata.
 */
function handleConnectRequest(clientReq, clientSocket, head) {
  const [host, port] = clientReq.url.split(':');
  const targetPort = parseInt(port) || 443;

  // Check if we should monitor this host
  if (config.targetHosts.length > 0 && !config.targetHosts.some(h => host.includes(h))) {
    // Not a target host, just tunnel without logging
    createTunnel(host, targetPort, clientSocket, head, false);
    return;
  }

  // Log the CONNECT request
  console.log(`\n🔒 HTTPS CONNECT: ${host}:${targetPort}`);

  // For full HTTPS inspection, you need TLS interception
  // This basic version creates a transparent tunnel
  createTunnel(host, targetPort, clientSocket, head, true);
}

/**
 * Create a tunnel to the target server
 */
function createTunnel(host, port, clientSocket, head, monitored) {
  const serverSocket = net.connect(port, host, () => {
    clientSocket.write(
      'HTTP/1.1 200 Connection Established\r\n' +
      'Proxy-Agent: AI-DLP-Proxy\r\n' +
      '\r\n'
    );

    serverSocket.write(head);

    // Track data for monitoring
    if (monitored) {
      let bytesSent = 0;
      let bytesReceived = 0;

      clientSocket.on('data', (chunk) => {
        bytesSent += chunk.length;
      });

      serverSocket.on('data', (chunk) => {
        bytesReceived += chunk.length;
      });

      const logStats = () => {
        if (bytesSent > 0 || bytesReceived > 0) {
          console.log(`   📊 ${host}: ↑${formatBytes(bytesSent)} ↓${formatBytes(bytesReceived)}`);
        }
      };

      clientSocket.on('end', logStats);
      serverSocket.on('end', logStats);
    }

    // Pipe data bidirectionally
    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  });

  serverSocket.on('error', (err) => {
    logError(`Tunnel error to ${host}:${port}`, err);
    clientSocket.end();
  });

  clientSocket.on('error', (err) => {
    serverSocket.end();
  });
}

/**
 * Format bytes to human readable
 */
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
  return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
}

// Start the server
server.listen(config.port, () => {
  logStartup(config.port);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\nShutting down proxy...');
  server.close(() => {
    console.log('Proxy stopped.');
    process.exit(0);
  });
});

process.on('uncaughtException', (err) => {
  logError('Uncaught exception', err);
});
