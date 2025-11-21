/**
 * Content Detection Module
 * Analyzes request bodies for potential data leakage indicators
 */

// Classification levels
const Classification = {
  SAFE: 'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  BLOCKED: 'BLOCKED'
};

// Detection patterns
const patterns = {
  // Credential patterns
  credentials: [
    /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[\w-]{20,}/gi,
    /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^'"\s]{8,}/gi,
    /(?:secret|token)\s*[:=]\s*['"]?[\w-]{20,}/gi,
    /(?:aws|azure|gcp)[_-]?(?:access|secret)[_-]?key\s*[:=]\s*['"]?[\w-]+/gi,
    /Bearer\s+[\w-]+\.[\w-]+\.[\w-]+/g, // JWT tokens
    /(?:ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/=]+/g, // SSH keys
    /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    /(?:mongodb|postgres|mysql|redis):\/\/[^\s]+/gi, // Connection strings
  ],

  // Code patterns
  codeIndicators: [
    /function\s+\w+\s*\([^)]*\)\s*\{/g,
    /class\s+\w+\s*(?:extends\s+\w+)?\s*\{/g,
    /(?:const|let|var)\s+\w+\s*=\s*(?:require|import)/g,
    /import\s+.*\s+from\s+['"][^'"]+['"]/g,
    /export\s+(?:default\s+)?(?:class|function|const)/g,
    /def\s+\w+\s*\([^)]*\)\s*:/g, // Python functions
    /class\s+\w+\s*(?:\([^)]*\))?\s*:/g, // Python classes
    /@\w+\s*(?:\([^)]*\))?\s*\n\s*(?:def|class)/g, // Python decorators
    /(?:public|private|protected)\s+(?:static\s+)?(?:void|int|string|bool)/gi,
  ],

  // Database/Schema patterns
  schemaPatterns: [
    /CREATE\s+TABLE\s+\w+/gi,
    /ALTER\s+TABLE\s+\w+/gi,
    /SELECT\s+.+\s+FROM\s+\w+/gi,
    /INSERT\s+INTO\s+\w+/gi,
    /UPDATE\s+\w+\s+SET/gi,
    /(?:PRIMARY\s+KEY|FOREIGN\s+KEY|REFERENCES)/gi,
    /(?:VARCHAR|INTEGER|BOOLEAN|TIMESTAMP|TEXT)\s*\(/gi,
  ],

  // File path patterns
  filePaths: [
    /(?:\/[\w.-]+){2,}/g, // Unix paths
    /[A-Z]:\\(?:[\w.-]+\\)+[\w.-]+/g, // Windows paths
    /\.(js|ts|py|java|cpp|c|go|rs|rb|php|swift|kt)\b/gi, // Source file extensions
    /(?:src|lib|app|components|utils|services|models)\/[\w.-]+/g,
  ],

  // Environment variable patterns
  envVariables: [
    /process\.env\.\w+/g,
    /\$\{?\w+\}?/g,
    /(?:NODE_ENV|DATABASE_URL|REDIS_URL|AWS_REGION)/g,
  ],
};

// Thresholds
const thresholds = {
  largeBodySize: 5000, // bytes
  suspiciousCodePatterns: 3,
  blockedCredentialPatterns: 1,
};

/**
 * Analyze content for potential data leakage
 * @param {string} body - Request body content
 * @param {string} contentType - Content-Type header
 * @returns {Object} Analysis result with classification and findings
 */
function analyzeContent(body, contentType = '') {
  const findings = {
    classification: Classification.SAFE,
    reasons: [],
    details: {
      credentials: [],
      codePatterns: [],
      schemaPatterns: [],
      filePaths: [],
      envVariables: [],
      bodySize: 0,
    },
  };

  if (!body || typeof body !== 'string') {
    return findings;
  }

  findings.details.bodySize = Buffer.byteLength(body, 'utf8');

  // Check body size
  if (findings.details.bodySize > thresholds.largeBodySize) {
    findings.reasons.push(`Large request body: ${findings.details.bodySize} bytes`);
  }

  // Check for credentials (BLOCKED level)
  for (const pattern of patterns.credentials) {
    const matches = body.match(pattern);
    if (matches) {
      findings.details.credentials.push(...matches.map(m => maskSensitive(m)));
      findings.classification = Classification.BLOCKED;
      findings.reasons.push(`Credential pattern detected: ${pattern.source}`);
    }
  }

  // Check for code patterns (SUSPICIOUS level)
  let codePatternCount = 0;
  for (const pattern of patterns.codeIndicators) {
    const matches = body.match(pattern);
    if (matches) {
      codePatternCount += matches.length;
      findings.details.codePatterns.push(...matches.slice(0, 3)); // Limit to 3 examples
    }
  }

  if (codePatternCount >= thresholds.suspiciousCodePatterns) {
    if (findings.classification !== Classification.BLOCKED) {
      findings.classification = Classification.SUSPICIOUS;
    }
    findings.reasons.push(`Code patterns detected: ${codePatternCount} occurrences`);
  }

  // Check for schema patterns
  for (const pattern of patterns.schemaPatterns) {
    const matches = body.match(pattern);
    if (matches) {
      findings.details.schemaPatterns.push(...matches.slice(0, 3));
      if (findings.classification === Classification.SAFE) {
        findings.classification = Classification.SUSPICIOUS;
      }
      findings.reasons.push(`Database schema pattern detected`);
      break;
    }
  }

  // Check for file paths
  for (const pattern of patterns.filePaths) {
    const matches = body.match(pattern);
    if (matches) {
      findings.details.filePaths.push(...matches.slice(0, 5));
      if (findings.classification === Classification.SAFE) {
        findings.classification = Classification.SUSPICIOUS;
      }
      findings.reasons.push(`File paths detected: ${matches.length} paths`);
      break;
    }
  }

  // Check for environment variables
  for (const pattern of patterns.envVariables) {
    const matches = body.match(pattern);
    if (matches) {
      findings.details.envVariables.push(...matches.slice(0, 3));
      if (findings.classification === Classification.SAFE) {
        findings.classification = Classification.SUSPICIOUS;
      }
      findings.reasons.push(`Environment variable references detected`);
      break;
    }
  }

  return findings;
}

/**
 * Mask sensitive data for logging
 * @param {string} value - Sensitive value
 * @returns {string} Masked value
 */
function maskSensitive(value) {
  if (value.length <= 8) {
    return '***';
  }
  return value.substring(0, 4) + '***' + value.substring(value.length - 4);
}

/**
 * Check if request should be blocked
 * @param {Object} findings - Analysis findings
 * @returns {boolean} Whether to block the request
 */
function shouldBlock(findings) {
  return findings.classification === Classification.BLOCKED;
}

module.exports = {
  analyzeContent,
  shouldBlock,
  Classification,
  patterns,
  thresholds,
};
