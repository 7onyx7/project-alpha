#!/bin/bash

# Make the email service test script executable
chmod +x ./tests/test-email-service.js

echo "Testing email service..."
node ./tests/test-email-service.js
