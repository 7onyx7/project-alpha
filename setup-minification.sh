#!/bin/bash

# Install required tools for minification
npm install -g terser clean-css-cli

# Install required dev dependencies
npm install --save-dev nodemon jest

# Create minified directory structure if not exists
mkdir -p public/scripts/min
mkdir -p public/styles/min

# Display success message
echo "Minification tools installed successfully!"
echo "You can now run 'npm run minify' to create minified versions of your CSS and JS files."
