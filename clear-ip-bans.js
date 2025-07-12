/**
 * Clear IP Ban Script
 * 
 * This script clears the IP ban from the security system
 */

const { bannedIPs, ipViolations } = require('./security');

console.log('🔧 Clearing IP Bans and Violations');
console.log('==================================');

// Clear all banned IPs
const bannedCount = bannedIPs.size;
const violationCount = ipViolations.size;

console.log(`📊 Current banned IPs: ${bannedCount}`);
console.log(`📊 Current IP violations: ${violationCount}`);

// Clear all bans
bannedIPs.clear();
ipViolations.clear();

console.log('✅ All IP bans cleared');
console.log('✅ All IP violations cleared');

console.log('\n📋 Current status:');
console.log(`📊 Banned IPs: ${bannedIPs.size}`);
console.log(`📊 IP violations: ${ipViolations.size}`);

process.exit(0);
