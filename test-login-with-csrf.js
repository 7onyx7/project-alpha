/**
 * Test Login API Endpoint with CSRF Token
 * 
 * This script tests the login API endpoint with proper CSRF token handling
 */

const http = require('http');

async function getCsrfToken() {
  console.log('🔐 Getting CSRF token...');
  
  const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/csrf-token',
    method: 'GET'
  };
  
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          console.log('🔐 CSRF Token retrieved:', jsonData.csrfToken ? 'Yes' : 'No');
          resolve(jsonData.csrfToken);
        } catch (error) {
          console.log('❌ Failed to get CSRF token:', data);
          resolve(null);
        }
      });
    });
    
    req.on('error', (error) => {
      console.error('❌ CSRF token request failed:', error.message);
      resolve(null);
    });
    
    req.end();
  });
}

async function testLoginWithCSRF(username, password, csrfToken) {
  console.log(`🧪 Testing login for user: ${username}`);
  
  const postData = JSON.stringify({
    username: username,
    password: password
  });
  
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData)
  };
  
  // Add CSRF token if available
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  
  const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/login',
    method: 'POST',
    headers: headers
  };
  
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      console.log(`📡 Response Status: ${res.statusCode}`);
      
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          console.log('📄 Response Body:', JSON.stringify(jsonData, null, 2));
          
          if (jsonData.success) {
            console.log('✅ Login successful!');
            console.log('🔑 Token received:', jsonData.token ? 'Yes' : 'No');
          } else {
            console.log('❌ Login failed:', jsonData.message);
          }
          
          resolve(jsonData);
        } catch (error) {
          console.log('❌ Failed to parse response:', data);
          reject(error);
        }
      });
    });
    
    req.on('error', (error) => {
      console.error('❌ Request failed:', error.message);
      reject(error);
    });
    
    req.write(postData);
    req.end();
  });
}

// Main test function
async function runTests() {
  console.log('🧪 Testing Login API with CSRF Protection');
  console.log('==========================================');
  
  try {
    // Get CSRF token first
    const csrfToken = await getCsrfToken();
    
    if (!csrfToken) {
      console.log('⚠️  No CSRF token available, testing without it...');
    }
    
    // Test 1: Valid credentials
    console.log('\n📋 Test 1: Valid credentials (admin/admin123!)');
    await testLoginWithCSRF('admin', 'admin123!', csrfToken);
    
    // Test 2: Invalid credentials
    console.log('\n📋 Test 2: Invalid credentials (admin/wrongpassword)');
    await testLoginWithCSRF('admin', 'wrongpassword', csrfToken);
    
    // Test 3: Missing username
    console.log('\n📋 Test 3: Missing username');
    await testLoginWithCSRF('', 'admin123!', csrfToken);
    
    // Test 4: Missing password
    console.log('\n📋 Test 4: Missing password');
    await testLoginWithCSRF('admin', '', csrfToken);
    
    console.log('\n✅ All tests completed');
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Test suite failed:', error);
    process.exit(1);
  }
}

// Run the tests
runTests();
