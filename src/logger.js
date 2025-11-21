/**
 * Logging Module
 * Provides formatted console output for proxy events
 */

const chalk = require('chalk');

// Color schemes for different classifications
const classificationColors = {
  SAFE: chalk.green,
  SUSPICIOUS: chalk.yellow,
  BLOCKED: chalk.red,
};

/**
 * Log a proxy request with analysis results
 * @param {Object} options - Logging options
 */
function logRequest(options) {
  const {
    method,
    url,
    host,
    headers,
    body,
    findings,
    timestamp = new Date(),
  } = options;

  const colorFn = classificationColors[findings.classification] || chalk.white;
  const separator = '═'.repeat(80);

  console.log('\n' + chalk.gray(separator));
  console.log(colorFn.bold(`[${findings.classification}] ${timestamp.toISOString()}`));
  console.log(chalk.gray('─'.repeat(80)));

  // Request info
  console.log(chalk.cyan('Request:'));
  console.log(`  Method: ${chalk.white(method)}`);
  console.log(`  URL: ${chalk.white(url)}`);
  console.log(`  Host: ${chalk.white(host)}`);

  // Headers (selected important ones)
  console.log(chalk.cyan('\nHeaders:'));
  const importantHeaders = ['content-type', 'authorization', 'user-agent', 'content-length'];
  for (const header of importantHeaders) {
    if (headers[header]) {
      const value = header === 'authorization'
        ? maskHeader(headers[header])
        : headers[header];
      console.log(`  ${header}: ${chalk.white(value)}`);
    }
  }

  // Body preview
  if (body) {
    console.log(chalk.cyan('\nBody Preview:'));
    const preview = body.length > 500 ? body.substring(0, 500) + '...' : body;
    console.log(chalk.gray(indent(preview, 2)));
  }

  // Analysis results
  if (findings.reasons.length > 0) {
    console.log(colorFn('\nFindings:'));
    for (const reason of findings.reasons) {
      console.log(colorFn(`  • ${reason}`));
    }
  }

  // Details
  const { details } = findings;

  if (details.credentials.length > 0) {
    console.log(chalk.red('\nCredentials Detected (MASKED):'));
    for (const cred of details.credentials) {
      console.log(chalk.red(`  ! ${cred}`));
    }
  }

  if (details.codePatterns.length > 0) {
    console.log(chalk.yellow('\nCode Patterns:'));
    for (const pattern of details.codePatterns.slice(0, 3)) {
      console.log(chalk.yellow(`  - ${truncate(pattern, 60)}`));
    }
  }

  if (details.schemaPatterns.length > 0) {
    console.log(chalk.yellow('\nSchema Patterns:'));
    for (const pattern of details.schemaPatterns) {
      console.log(chalk.yellow(`  - ${pattern}`));
    }
  }

  if (details.filePaths.length > 0) {
    console.log(chalk.yellow('\nFile Paths:'));
    for (const path of details.filePaths.slice(0, 5)) {
      console.log(chalk.yellow(`  - ${path}`));
    }
  }

  console.log(chalk.gray('\n' + separator));
}

/**
 * Log proxy startup information
 * @param {number} port - Proxy port
 */
function logStartup(port) {
  console.log(chalk.green.bold('\n🛡️  AI DLP Proxy Started'));
  console.log(chalk.gray('─'.repeat(40)));
  console.log(`  Port: ${chalk.cyan(port)}`);
  console.log(`  Mode: ${chalk.cyan('HTTP/HTTPS CONNECT')}`);
  console.log(chalk.gray('─'.repeat(40)));
  console.log(chalk.yellow('\nConfiguration:'));
  console.log(`  macOS: System Preferences → Network → Proxies`);
  console.log(`         Set HTTPS Proxy to localhost:${port}`);
  console.log(`  Env:   export HTTPS_PROXY=http://localhost:${port}`);
  console.log(chalk.gray('\nWaiting for connections...\n'));
}

/**
 * Log an error
 * @param {string} message - Error message
 * @param {Error} error - Error object
 */
function logError(message, error) {
  console.error(chalk.red(`\n❌ ${message}`));
  if (error) {
    console.error(chalk.red(`   ${error.message}`));
  }
}

/**
 * Log a blocked request
 * @param {string} url - Blocked URL
 * @param {Array} reasons - Blocking reasons
 */
function logBlocked(url, reasons) {
  console.log(chalk.red.bold(`\n🚫 REQUEST BLOCKED`));
  console.log(chalk.red(`   URL: ${url}`));
  console.log(chalk.red(`   Reasons:`));
  for (const reason of reasons) {
    console.log(chalk.red(`   - ${reason}`));
  }
}

// Helper functions
function indent(text, spaces) {
  const pad = ' '.repeat(spaces);
  return text.split('\n').map(line => pad + line).join('\n');
}

function truncate(text, maxLength) {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

function maskHeader(value) {
  if (value.length <= 10) return '***';
  return value.substring(0, 7) + '***';
}

module.exports = {
  logRequest,
  logStartup,
  logError,
  logBlocked,
};
