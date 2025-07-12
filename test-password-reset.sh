#!/bin/bash

# Make the password reset test script executable
chmod +x ./tests/password-reset-test.js

echo "Testing password reset functionality..."
node ./tests/password-reset-test.js
