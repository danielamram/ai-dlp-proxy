/**
 * AI DLP Proxy - Data Leakage Prevention Proxy for AI Tools
 *
 * This proxy intercepts HTTPS traffic and analyzes it for potential
 * data leakage indicators such as credentials, code, and sensitive data.
 */

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const { URL } = require('url');
const { analyzeContent, shouldBlock } = require('./detector');
const { logRequest, logStartup, logError, logBlocked } = require('./logger');
const { getOrCreateCA, generateCertificate, getCertPaths } = require('./cert-generator');

// Initialize CA certificate
let caInfo = null;
try {
  caInfo = getOrCreateCA();
  console.log('✅ CA certificate loaded');
} catch (err) {
  console.error('❌ Failed to initialize CA certificate:', err.message);
  process.exit(1);
}

// Configuration
const config = {
  port: parseInt(process.env.PROXY_PORT) || 8888,
  blockMode: process.env.BLOCK_MODE === 'true', // Set to true to block suspicious requests
  logFullBody: process.env.LOG_FULL_BODY === 'true',
  targetHosts: (process.env.TARGET_HOSTS || '').split(',').filter(Boolean), // Empty = all hosts
  tlsIntercept: process.env.TLS_INTERCEPT !== 'false', // TLS interception enabled by default
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
 * With TLS interception enabled, this will decrypt, analyze, and re-encrypt traffic.
 * Without TLS interception, creates a transparent tunnel.
 */
function handleConnectRequest(clientReq, clientSocket, head) {
  const [host, port] = clientReq.url.split(':');
  const targetPort = parseInt(port) || 443;

  // Check if we should monitor this host
  const shouldMonitor = config.targetHosts.length === 0 || 
                        config.targetHosts.some(h => host.includes(h));

  if (!shouldMonitor) {
    // Not a target host, just tunnel without logging
    createTunnel(host, targetPort, clientSocket, head, false);
    return;
  }

  // Log the CONNECT request
  console.log(`\n🔒 HTTPS CONNECT: ${host}:${targetPort}`);

  // Use TLS interception if enabled
  if (config.tlsIntercept) {
    interceptTLS(host, targetPort, clientSocket, head);
  } else {
    createTunnel(host, targetPort, clientSocket, head, true);
  }
}

/**
 * Intercept TLS traffic - decrypt, analyze, and re-encrypt
 */
function interceptTLS(host, port, clientSocket, head) {
  // Generate certificate for this domain
  const certData = generateCertificate(host, caInfo);

  // Send connection established response
  clientSocket.write(
    'HTTP/1.1 200 Connection Established\r\n' +
    'Proxy-Agent: AI-DLP-Proxy\r\n' +
    '\r\n'
  );

  // Create TLS connection with client using our certificate
  const tlsOptions = {
    key: certData.key,
    cert: certData.cert,
    SNICallback: (servername, cb) => {
      // Generate cert for SNI hostname if different
      const sniCert = generateCertificate(servername, caInfo);
      cb(null, tls.createSecureContext({
        key: sniCert.key,
        cert: sniCert.cert,
      }));
    },
  };

  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    server: server,
    ...tlsOptions,
  });

  // Handle TLS errors
  tlsSocket.on('error', (err) => {
    logError(`TLS socket error for ${host}`, err);
    clientSocket.end();
  });

  // Parse HTTP requests from the decrypted TLS connection
  let buffer = '';
  let isParsingBody = false;
  let currentRequest = null;
  let bodyBytesRead = 0;
  let contentLength = 0;

  tlsSocket.on('data', (chunk) => {
    buffer += chunk.toString();

    // Parse HTTP request
    if (!isParsingBody) {
      const headerEndIndex = buffer.indexOf('\r\n\r\n');
      if (headerEndIndex !== -1) {
        const headerSection = buffer.substring(0, headerEndIndex);
        const lines = headerSection.split('\r\n');
        const requestLine = lines[0].split(' ');

        const method = requestLine[0];
        const path = requestLine[1];
        const headers = {};

        for (let i = 1; i < lines.length; i++) {
          const colonIndex = lines[i].indexOf(':');
          if (colonIndex !== -1) {
            const key = lines[i].substring(0, colonIndex).toLowerCase();
            const value = lines[i].substring(colonIndex + 1).trim();
            headers[key] = value;
          }
        }

        contentLength = parseInt(headers['content-length'] || '0');
        currentRequest = {
          method,
          path,
          headers,
          url: `https://${host}${path}`,
        };

        buffer = buffer.substring(headerEndIndex + 4);
        bodyBytesRead = buffer.length;
        isParsingBody = contentLength > 0;

        if (!isParsingBody) {
          // No body, forward immediately
          forwardRequest(host, port, currentRequest, '', tlsSocket);
          currentRequest = null;
          buffer = '';
        }
      }
    }

    if (isParsingBody && currentRequest) {
      bodyBytesRead = buffer.length;
      if (bodyBytesRead >= contentLength) {
        const body = buffer.substring(0, contentLength);
        buffer = buffer.substring(contentLength);

        // Analyze and forward
        forwardRequest(host, port, currentRequest, body, tlsSocket);

        // Reset for next request
        currentRequest = null;
        isParsingBody = false;
        bodyBytesRead = 0;
      }
    }
  });

  tlsSocket.on('end', () => {
    clientSocket.end();
  });
}

/**
 * Forward the analyzed request to the target server
 */
function forwardRequest(host, port, requestData, body, clientTlsSocket) {
  // Analyze the request
  const findings = analyzeContent(body, requestData.headers['content-type']);

  logRequest({
    method: requestData.method,
    url: requestData.url,
    host: host,
    headers: requestData.headers,
    body: config.logFullBody ? body : body.substring(0, 1000),
    findings,
  });

  // Block if configured and findings warrant it
  if (config.blockMode && shouldBlock(findings)) {
    logBlocked(requestData.url, findings.reasons);
    const response = 'HTTP/1.1 403 Forbidden\r\n' +
                     'Content-Type: text/plain\r\n' +
                     'Content-Length: 56\r\n' +
                     '\r\n' +
                     'Request blocked by DLP proxy: Sensitive content detected';
    clientTlsSocket.write(response);
    return;
  }

  // Forward to target server
  const options = {
    hostname: host,
    port: port,
    path: requestData.path,
    method: requestData.method,
    headers: requestData.headers,
  };

  const proxyReq = https.request(options, (proxyRes) => {
    // Forward status and headers
    let response = `HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage}\r\n`;
    for (const [key, value] of Object.entries(proxyRes.headers)) {
      response += `${key}: ${value}\r\n`;
    }
    response += '\r\n';
    clientTlsSocket.write(response);

    // Forward response body
    proxyRes.on('data', (chunk) => {
      clientTlsSocket.write(chunk);
    });

    proxyRes.on('end', () => {
      // Response complete
    });
  });

  proxyReq.on('error', (err) => {
    logError(`Proxy request error to ${host}`, err);
    const errorResponse = 'HTTP/1.1 502 Bad Gateway\r\n' +
                         'Content-Type: text/plain\r\n' +
                         'Content-Length: 11\r\n' +
                         '\r\n' +
                         'Proxy error';
    clientTlsSocket.write(errorResponse);
  });

  if (body) {
    proxyReq.write(body);
  }
  proxyReq.end();
}

/**
 * Create a transparent tunnel to the target server (no interception)
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
  
  if (config.tlsIntercept) {
    console.log('🔓 TLS Interception: ENABLED');
    console.log('📜 CA Certificate: ' + getCertPaths().caCert);
    console.log('⚠️  Install and trust the CA certificate to avoid browser warnings');
    console.log('   Run: node src/setup-cert.js');
  } else {
    console.log('🔓 TLS Interception: DISABLED (transparent tunnel mode)');
    console.log('   Set TLS_INTERCEPT=true to enable content inspection');
  }
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
