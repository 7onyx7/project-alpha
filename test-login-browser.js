/**
 * Simple Login Test with User Agent
 * 
 * This script tests login with a proper user agent to avoid security blocks
 */

const http = require('http');

async function testWithUserAgent() {
  console.log('🧪 Testing Login with Proper User Agent');
  console.log('=======================================');
  
  // First, test if we can get the CSRF token
  console.log('🔐 Testing CSRF token endpoint...');
  
  const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/csrf-token',
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  };
  
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      console.log(`📡 CSRF Response Status: ${res.statusCode}`);
      
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          console.log('📄 CSRF Response:', JSON.stringify(jsonData, null, 2));
          
          if (jsonData.csrfToken) {
            console.log('✅ CSRF token retrieved successfully');
            testLoginWithToken(jsonData.csrfToken);
          } else {
            console.log('❌ No CSRF token in response');
          }
          
          resolve(jsonData);
        } catch (error) {
          console.log('❌ Failed to parse CSRF response:', data);
          reject(error);
        }
      });
    });
    
    req.on('error', (error) => {
      console.error('❌ CSRF request failed:', error.message);
      reject(error);
    });
    
    req.end();
  });
}

async function testLoginWithToken(csrfToken) {
  console.log('\n🔑 Testing login with CSRF token...');
  
  const postData = JSON.stringify({
    username: 'admin',
    password: 'admin123!'
  });
  
  const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData),
      'X-CSRF-Token': csrfToken,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  };
  
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      console.log(`📡 Login Response Status: ${res.statusCode}`);
      
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          console.log('📄 Login Response:', JSON.stringify(jsonData, null, 2));
          
          if (jsonData.success) {
            console.log('🎉 LOGIN SUCCESSFUL!');
            console.log('🔑 Token received:', jsonData.token ? 'Yes' : 'No');
            console.log('👤 User:', jsonData.username || 'Not provided');
          } else {
            console.log('❌ Login failed:', jsonData.message);
          }
          
          resolve(jsonData);
        } catch (error) {
          console.log('❌ Failed to parse login response:', data);
          reject(error);
        }
      });
    });
    
    req.on('error', (error) => {
      console.error('❌ Login request failed:', error.message);
      reject(error);
    });
    
    req.write(postData);
    req.end();
  });
}

// Run the test
testWithUserAgent()
  .then(() => {
    console.log('\n✅ Test completed');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Test failed:', error);
    process.exit(1);
  });
