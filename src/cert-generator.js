/**
 * Certificate Generator for TLS Interception
 * 
 * Generates a CA certificate and on-the-fly certificates for proxied domains.
 */

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const CERT_DIR = path.join(__dirname, '../certs');
const CA_KEY_PATH = path.join(CERT_DIR, 'ca-key.pem');
const CA_CERT_PATH = path.join(CERT_DIR, 'ca-cert.pem');

// Cache for generated certificates
const certCache = new Map();

/**
 * Ensure the certs directory exists
 */
function ensureCertDir() {
  if (!fs.existsSync(CERT_DIR)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
  }
}

/**
 * Generate or load CA certificate
 */
function getOrCreateCA() {
  ensureCertDir();

  // Check if CA already exists
  if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
    const caKey = fs.readFileSync(CA_KEY_PATH, 'utf8');
    const caCert = fs.readFileSync(CA_CERT_PATH, 'utf8');
    
    return {
      key: forge.pki.privateKeyFromPem(caKey),
      cert: forge.pki.certificateFromPem(caCert),
      keyPem: caKey,
      certPem: caCert,
    };
  }

  // Generate new CA
  console.log('🔐 Generating CA certificate...');
  
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  
  const attrs = [
    { name: 'commonName', value: 'AI DLP Proxy CA' },
    { name: 'countryName', value: 'US' },
    { name: 'organizationName', value: 'AI DLP Proxy' },
    { shortName: 'OU', value: 'Development' },
  ];
  
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
  ]);
  
  // Self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());
  
  // Convert to PEM format
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const certPem = forge.pki.certificateToPem(cert);
  
  // Save to disk
  fs.writeFileSync(CA_KEY_PATH, keyPem);
  fs.writeFileSync(CA_CERT_PATH, certPem);
  
  console.log('✅ CA certificate generated');
  console.log(`   Key:  ${CA_KEY_PATH}`);
  console.log(`   Cert: ${CA_CERT_PATH}`);
  
  return {
    key: keys.privateKey,
    cert: cert,
    keyPem,
    certPem,
  };
}

/**
 * Generate a certificate for a specific domain
 */
function generateCertificate(domain, ca) {
  // Check cache
  if (certCache.has(domain)) {
    return certCache.get(domain);
  }

  // Generate new certificate for this domain
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Math.floor(Math.random() * 1000000).toString();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  
  const attrs = [
    { name: 'commonName', value: domain },
    { name: 'countryName', value: 'US' },
    { name: 'organizationName', value: 'AI DLP Proxy' },
  ];
  
  cert.setSubject(attrs);
  cert.setIssuer(ca.cert.subject.attributes);
  
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
    },
    {
      name: 'subjectAltName',
      altNames: [
        {
          type: 2, // DNS
          value: domain,
        },
        {
          type: 2, // DNS - wildcard
          value: '*.' + domain,
        },
      ],
    },
  ]);
  
  // Sign with CA
  cert.sign(ca.key, forge.md.sha256.create());
  
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  
  const result = {
    key: keyPem,
    cert: certPem,
  };
  
  // Cache it
  certCache.set(domain, result);
  
  return result;
}

/**
 * Get certificate paths for installation
 */
function getCertPaths() {
  return {
    caKey: CA_KEY_PATH,
    caCert: CA_CERT_PATH,
    certDir: CERT_DIR,
  };
}

module.exports = {
  getOrCreateCA,
  generateCertificate,
  getCertPaths,
};

