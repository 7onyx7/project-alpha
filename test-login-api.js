/**
 * Test Login API Endpoint
 * 
 * This script tests the login API endpoint directly
 */

const https = require('http');

async function testLoginAPI() {
  console.log('🧪 Testing Login API Endpoint');
  console.log('==============================');
  
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
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      console.log(`📡 Response Status: ${res.statusCode}`);
      console.log(`📡 Response Headers:`, res.headers);
      
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
    
    // Send the request
    req.write(postData);
    req.end();
  });
}

// Test with valid credentials
testLoginAPI()
  .then(() => {
    console.log('\n🧪 Testing with invalid credentials...');
    
    // Test with invalid credentials
    const postData = JSON.stringify({
      username: 'admin',
      password: 'wrongpassword'
    });
    
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: '/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        console.log(`📡 Response Status: ${res.statusCode}`);
        
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          try {
            const jsonData = JSON.parse(data);
            console.log('📄 Response Body:', JSON.stringify(jsonData, null, 2));
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
  })
  .then(() => {
    console.log('\n✅ All tests completed');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Test failed:', error);
    process.exit(1);
  });
