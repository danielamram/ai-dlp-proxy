#!/usr/bin/env node

/**
 * Certificate Setup Script
 * 
 * Guides users through installing and trusting the CA certificate
 * for TLS interception.
 */

const { getOrCreateCA, getCertPaths } = require('./cert-generator');
const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');

console.log('\n🔐 AI DLP Proxy - Certificate Setup\n');
console.log('This script will help you install and trust the CA certificate');
console.log('for HTTPS traffic inspection.\n');

// Generate or load CA
try {
  const ca = getOrCreateCA();
  const paths = getCertPaths();
  
  console.log('✅ CA Certificate ready');
  console.log(`   Location: ${paths.caCert}\n`);
  
  // Detect OS
  const platform = os.platform();
  
  if (platform === 'darwin') {
    setupMacOS(paths.caCert);
  } else if (platform === 'linux') {
    setupLinux(paths.caCert);
  } else if (platform === 'win32') {
    setupWindows(paths.caCert);
  } else {
    console.log('❓ Unknown platform. Manual installation required.');
    showManualInstructions(paths.caCert);
  }
  
} catch (err) {
  console.error('❌ Setup failed:', err.message);
  process.exit(1);
}

/**
 * Setup for macOS
 */
function setupMacOS(certPath) {
  console.log('📱 Detected macOS\n');
  console.log('Installing CA certificate to System Keychain...\n');
  
  try {
    // Add certificate to system keychain
    console.log('This will require administrator privileges (sudo).');
    execSync(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${certPath}"`, {
      stdio: 'inherit',
    });
    
    console.log('\n✅ Certificate installed and trusted!');
    console.log('\n📝 Next steps:');
    console.log('   1. Restart your browser or application (e.g., Cursor)');
    console.log('   2. Start the proxy: npm start');
    console.log('   3. Configure your app to use the proxy\n');
    
  } catch (err) {
    console.log('\n⚠️  Automatic installation failed.');
    console.log('Please install manually:\n');
    console.log('1. Open Keychain Access app');
    console.log(`2. File → Import Items → Select: ${certPath}`);
    console.log('3. Double-click "AI DLP Proxy CA" in System keychain');
    console.log('4. Expand "Trust" section');
    console.log('5. Set "When using this certificate" to "Always Trust"');
    console.log('6. Close and enter your password\n');
  }
}

/**
 * Setup for Linux
 */
function setupLinux(certPath) {
  console.log('🐧 Detected Linux\n');
  
  // Check for certificate directory
  const certDirs = [
    '/usr/local/share/ca-certificates',
    '/etc/pki/ca-trust/source/anchors',
    '/etc/ca-certificates/trust-source/anchors',
  ];
  
  let foundDir = null;
  for (const dir of certDirs) {
    if (fs.existsSync(dir)) {
      foundDir = dir;
      break;
    }
  }
  
  if (foundDir) {
    console.log(`Installing to: ${foundDir}\n`);
    try {
      const targetPath = `${foundDir}/ai-dlp-proxy-ca.crt`;
      execSync(`sudo cp "${certPath}" "${targetPath}"`, { stdio: 'inherit' });
      
      // Update certificates
      if (fs.existsSync('/usr/sbin/update-ca-certificates')) {
        execSync('sudo update-ca-certificates', { stdio: 'inherit' });
      } else if (fs.existsSync('/usr/bin/update-ca-trust')) {
        execSync('sudo update-ca-trust', { stdio: 'inherit' });
      }
      
      console.log('\n✅ Certificate installed!');
      console.log('\n📝 Next steps:');
      console.log('   1. Restart your browser or application');
      console.log('   2. Start the proxy: npm start\n');
      
    } catch (err) {
      console.log('\n⚠️  Automatic installation failed.');
      showManualInstructions(certPath);
    }
  } else {
    console.log('⚠️  Could not find certificate directory.');
    showManualInstructions(certPath);
  }
}

/**
 * Setup for Windows
 */
function setupWindows(certPath) {
  console.log('🪟 Detected Windows\n');
  console.log('To install the certificate:\n');
  console.log('1. Open Certificate Manager (certmgr.msc)');
  console.log('2. Navigate to: Trusted Root Certification Authorities → Certificates');
  console.log('3. Right-click → All Tasks → Import');
  console.log(`4. Select file: ${certPath}`);
  console.log('5. Choose "Trusted Root Certification Authorities" store');
  console.log('6. Click Finish\n');
  console.log('Or run as Administrator:');
  console.log(`   certutil -addstore -f "ROOT" "${certPath}"\n`);
}

/**
 * Show manual installation instructions
 */
function showManualInstructions(certPath) {
  console.log('\n📖 Manual Installation Instructions:\n');
  console.log(`Certificate location: ${certPath}\n`);
  console.log('To trust this certificate:');
  console.log('1. Import the certificate to your system\'s trusted root store');
  console.log('2. Configure your application to trust system certificates');
  console.log('3. Restart the application\n');
  console.log('For browsers:');
  console.log('- Firefox: Preferences → Privacy & Security → Certificates → View Certificates');
  console.log('- Chrome/Edge: Uses system certificate store\n');
}

console.log('═══════════════════════════════════════════════════════════════\n');

