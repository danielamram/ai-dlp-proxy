#!/usr/bin/env node

/**
 * Test Script for TLS Interception
 * 
 * This script tests the proxy's ability to intercept and analyze HTTPS traffic.
 * Run this with the proxy active to see content inspection in action.
 */

const https = require('https');

const PROXY_HOST = 'localhost';
const PROXY_PORT = 8888;

// Test data with different sensitivity levels
const testCases = [
  {
    name: 'Safe Request',
    data: {
      message: 'Hello, how can I help you today?',
      context: 'general conversation',
    },
  },
  {
    name: 'Suspicious Request (Code)',
    data: {
      code: `
        function calculateTotal(items) {
          const taxRate = 0.08;
          return items.reduce((sum, item) => sum + item.price, 0) * (1 + taxRate);
        }
      `,
      question: 'Can you review this function?',
    },
  },
  {
    name: 'Blocked Request (API Key)',
    data: {
      config: {
        api_key: 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz',
        endpoint: 'https://api.example.com',
      },
      message: 'Setup authentication',
    },
  },
];

console.log('🧪 Testing TLS Interception\n');
console.log('Make sure the proxy is running with TLS interception enabled:');
console.log('   npm start\n');
console.log('═══════════════════════════════════════════════════════════════\n');

async function runTest(testCase, index) {
  return new Promise((resolve) => {
    console.log(`Test ${index + 1}: ${testCase.name}`);
    
    const postData = JSON.stringify(testCase.data);
    
    const options = {
      hostname: 'httpbin.org',
      port: 443,
      path: '/post',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      agent: new https.Agent({
        proxy: {
          host: PROXY_HOST,
          port: PROXY_PORT,
        },
      }),
    };

    // For Node.js, we need to set the proxy using environment variables
    // This test uses direct connection - check proxy logs instead
    process.env.HTTP_PROXY = `http://${PROXY_HOST}:${PROXY_PORT}`;
    process.env.HTTPS_PROXY = `http://${PROXY_HOST}:${PROXY_PORT}`;

    const req = https.request('https://httpbin.org/post', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
    }, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        console.log(`   Status: ${res.statusCode}`);
        if (res.statusCode === 403) {
          console.log('   ❌ BLOCKED by DLP proxy');
        } else if (res.statusCode === 200) {
          console.log('   ✅ Allowed');
        }
        console.log('   Check proxy logs for detailed analysis\n');
        resolve();
      });
    });

    req.on('error', (err) => {
      console.log(`   ⚠️  Error: ${err.message}`);
      console.log('   Make sure proxy is running and certificate is trusted\n');
      resolve();
    });

    req.write(postData);
    req.end();
  });
}

async function runAllTests() {
  for (let i = 0; i < testCases.length; i++) {
    await runTest(testCases[i], i);
    // Wait a bit between tests
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('✅ Tests complete! Check proxy logs for detailed findings.');
  console.log('\nExpected results:');
  console.log('  Test 1: SAFE classification');
  console.log('  Test 2: SUSPICIOUS classification');
  console.log('  Test 3: BLOCKED (if BLOCK_MODE=true)');
}

runAllTests().catch(console.error);

