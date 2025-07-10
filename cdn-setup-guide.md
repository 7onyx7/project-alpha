# CDN Setup Guide for Project Alpha

## Cloudflare CDN Setup Instructions

### 1. Create a Cloudflare Account
- Go to [Cloudflare.com](https://www.cloudflare.com/) and sign up for a free account

### 2. Add Your Domain
- After logging in, click "Add Site"
- Enter your domain name (e.g., `projectalpha.com`)
- Select the Free plan
- Follow the instructions to update your nameservers at your domain registrar

### 3. Configure Cloudflare for Your Project

#### Enable Caching:
1. Go to the "Caching" tab in your Cloudflare dashboard
2. Under "Configuration":
   - Set Standard caching level: "Standard"
   - Browser Cache TTL: "4 hours"
   - Enable "Always Online"

#### Create a Page Rule for Static Assets:
1. Go to "Rules" > "Page Rules"
2. Create a new Page Rule with the URL pattern: `*projectalpha.com/public/*`
3. Add the following settings:
   - Cache Level: Cache Everything
   - Edge Cache TTL: 2 hours
   - Browser Cache TTL: 1 hour

### 4. Update Your Code to Use Cloudflare CDN URLs

Once your domain is active on Cloudflare, update your HTML files to use your CDN URLs for static assets:

```html
<!-- Before -->
<link rel="stylesheet" href="styles/styles.css" />

<!-- After -->
<link rel="stylesheet" href="https://your-domain.com/styles/styles.css" />
```

## Alternative: Using jsDelivr (Free Open Source CDN)

If you don't have a custom domain, you can use jsDelivr with your GitHub repository:

1. Push your code to a public GitHub repository
2. Use the following URL pattern in your HTML:

```html
<!-- For CSS files -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/username/project-alpha@main/public/styles/styles.css" />

<!-- For JavaScript files -->
<script src="https://cdn.jsdelivr.net/gh/username/project-alpha@main/public/scripts/scripts.js"></script>
```

Replace `username` with your GitHub username and `main` with your branch name.

## Creating Minified Versions of Your Files

### Install Minification Tools:
```bash
npm install -g terser clean-css-cli
```

### Minify JavaScript Files:
```bash
terser public/scripts/scripts.js -o public/scripts/scripts.min.js
terser public/scripts/login.js -o public/scripts/login.min.js
terser public/scripts/chat.js -o public/scripts/chat.min.js
terser public/scripts/csrf.js -o public/scripts/csrf.min.js
```

### Minify CSS Files:
```bash
cleancss -o public/styles/styles.min.css public/styles/styles.css
cleancss -o public/styles/login.min.css public/styles/login.css
cleancss -o public/styles/chat.min.css public/styles/chat.css
```

### Update HTML Files to Use Minified Versions:
```html
<!-- Before -->
<link rel="stylesheet" href="styles/styles.css" />

<!-- After -->
<link rel="stylesheet" href="styles/styles.min.css" />
```
