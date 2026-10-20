/\*\*  
 \* CSPForge Pro \- Multi-Framework Production Middleware & Nonce Synthesizer  
 \* Generates ready-to-deploy CSP middleware with dynamic per-request cryptographic nonces.  
 \*/

class MiddlewareSynthesizer {  
  constructor(policyInput) {  
    if (typeof policyInput \=== 'string') {  
      this.rawPolicy \= policyInput.trim();  
      this.directives \= this.parsePolicy(this.rawPolicy);  
    } else if (typeof policyInput \=== 'object' && policyInput \!== null) {  
      this.directives \= policyInput.directives || policyInput;  
      this.rawPolicy \= this.serializePolicy(this.directives);  
    } else {  
      this.directives \= {};  
      this.rawPolicy \= "";  
    }  
  }

  parsePolicy(str) {  
    const map \= {};  
    if (\!str) return map;  
    str.split(';').forEach(p \=\> {  
      const tokens \= p.trim().split(/\\s+/).filter(Boolean);  
      if (tokens.length \> 0\) {  
        map\[tokens\[0\].toLowerCase()\] \= tokens.slice(1);  
      }  
    });  
    return map;  
  }

  serializePolicy(dirs) {  
    return Object.entries(dirs)  
      .map((\[k, v\]) \=\> Array.isArray(v) ? \`\${k} \${v.join(' ')}\` : k)  
      .join('; ');  
  }

  generateNextJS() {  
    return \`// Next.js 14 / 15 App Router Edge Middleware (middleware.ts)  
// Injects per-request cryptographic nonces into both CSP headers and request context  
import { NextResponse } from 'next/server';  
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {  
  // Generate a cryptographically random Base64 nonce  
  const nonce \= Buffer.from(crypto.randomUUID()).toString('base64');  
    
  // Construct the hardened CSP Level 3 policy  
  const cspHeader \= \\\`  
    default-src 'self';  
    script-src 'self' 'nonce-\\\${nonce}' 'strict-dynamic' https: 'unsafe-inline';  
    style-src 'self' 'nonce-\\\${nonce}' https: 'unsafe-inline';  
    img-src 'self' blob: data: https:;  
    font-src 'self' data: https:;  
    object-src 'none';  
    base-uri 'self';  
    form-action 'self';  
    frame-ancestors 'none';  
    upgrade-insecure-requests;  
  \\\`.replace(/\\\\s{2,}/g, ' ').trim();

  // Forward nonce in internal request header so server components can read it  
  const requestHeaders \= new Headers(request.headers);  
  requestHeaders.set('x-nonce', nonce);  
  requestHeaders.set('Content-Security-Policy', cspHeader);

  const response \= NextResponse.next({  
    request: {  
      headers: requestHeaders,  
    },  
  });

  // Set Content-Security-Policy header on outbound HTTP response  
  response.headers.set('Content-Security-Policy', cspHeader);  
  return response;  
}

export const config \= {  
  matcher: \[  
    // Apply CSP to all paths except static assets, favicon, and image optimization  
    '/((?\!api|\_next/static|\_next/image|favicon.ico).\*)',  
  \],  
};\`;  
  }

  generateExpress() {  
    return \`// Node.js Express.js CSP Middleware with Per-Request Nonce Generation  
const express \= require('express');  
const crypto \= require('crypto');

const app \= express();

// Middleware: Generate per-request cryptographic nonce and emit CSP header  
app.use((req, res, next) \=\> {  
  // Generate 16 bytes of cryptographically secure random data  
  const nonce \= crypto.randomBytes(16).toString('base64');  
  res.locals.cspNonce \= nonce;

  const policy \= \[  
    "default-src 'self'",  
    \\\`script-src 'self' 'nonce-\\\${nonce}' 'strict-dynamic' https: 'unsafe-inline'\\\`,  
    \\\`style-src 'self' 'nonce-\\\${nonce}' https: 'unsafe-inline'\\\`,  
    "img-src 'self' data: https:",  
    "font-src 'self' https:",  
    "object-src 'none'",  
    "base-uri 'self'",  
    "form-action 'self'",  
    "frame-ancestors 'none'",  
    "upgrade-insecure-requests"  
  \].join('; ');

  res.setHeader('Content-Security-Policy', policy);  
  next();  
});

// Render view using nonce in EJS/Pug templates: \<script nonce="\<%= cspNonce %\>"\>  
app.get('/', (req, res) \=\> {  
  res.send(\\\`  
    \<\!DOCTYPE html\>  
    \<html\>  
      \<head\>  
        \<title\>CSP Secured\</title\>  
      \</head\>  
      \<body\>  
        \<h1\>Protected by CSPForge Pro\</h1\>  
        \<script nonce="\\\${res.locals.cspNonce}"\>  
          console.log('Authorized nonced script executed safely.');  
        \</script\>  
      \</body\>  
    \</html\>  
  \\\`);  
});

module.exports \= app;\`;  
  }

  generateFastAPI() {  
    return \`\# Python FastAPI / Starlette Dynamic Nonce CSP Middleware  
import secrets  
from fastapi import FastAPI, Request  
from starlette.middleware.base import BaseHTTPMiddleware  
from starlette.responses import Response

app \= FastAPI(title="CSP Hardened API")

class ContentSecurityPolicyMiddleware(BaseHTTPMiddleware):  
    async def dispatch(self, request: Request, call\_next):  
        \# Generate 128-bit cryptographically secure random nonce  
        nonce \= secrets.token\_urlsafe(16)  
        request.state.csp\_nonce \= nonce

        response: Response \= await call\_next(request)

        \# Assemble CSP directives  
        csp\_policy \= (  
            "default-src 'self'; "  
            f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic' https: 'unsafe-inline'; "  
            f"style-src 'self' 'nonce-{nonce}' https: 'unsafe-inline'; "  
            "img-src 'self' data: https:; "  
            "font-src 'self' https:; "  
            "object-src 'none'; "  
            "base-uri 'self'; "  
            "form-action 'self'; "  
            "frame-ancestors 'none'; "  
            "upgrade-insecure-requests"  
        )  
        response.headers\["Content-Security-Policy"\] \= csp\_policy  
        return response

app.add\_middleware(ContentSecurityPolicyMiddleware)

@app.get("/")  
async def root(request: Request):  
    return {  
        "status": "secure",  
        "active\_nonce": request.state.csp\_nonce  
    }  
\`;  
  }

  generateNginx() {  
    const formattedPolicy \= this.rawPolicy.replace(/"/g, '\\\\"');  
    return \`\# Nginx Server Block (nginx.conf)  
\# Place inside the 'server' or 'location' context

server {  
    listen 443 ssl http2;  
    server\_name app.example.com;

    \# Content-Security-Policy Header  
    add\_header Content-Security-Policy "\${formattedPolicy}" always;

    \# Complementary Security Headers  
    add\_header X-Content-Type-Options "nosniff" always;  
    add\_header Referrer-Policy "strict-origin-when-cross-origin" always;  
    add\_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    location / {  
        proxy\_pass http\://backend\_upstream;  
        proxy\_set\_header Host \$host;  
    }  
}\`;  
  }

  generateApache() {  
    const formattedPolicy \= this.rawPolicy.replace(/"/g, '\\\\"');  
    return \`\# Apache HTTP Server (.htaccess / httpd.conf)  
\<IfModule mod\_headers.c\>  
    Header always set Content-Security-Policy "\${formattedPolicy}"  
    Header always set X-Content-Type-Options "nosniff"  
    Header always set Referrer-Policy "strict-origin-when-cross-origin"  
\</IfModule\>\`;  
  }

  generateMetaTag() {  
    const cleanPolicy \= this.rawPolicy.replace(/"/g, '\&quot;');  
    return \`\<\!-- HTML5 Document Head Meta Tag \--\>  
\<\!-- Note: 'frame-ancestors', 'report-uri', and 'sandbox' directives cannot be set via meta tags per W3C spec \--\>  
\<meta http-equiv="Content-Security-Policy" content="\${cleanPolicy}"\>\`;  
  }  
}

if (typeof module \!== 'undefined' && module.exports) {  
  module.exports \= { MiddlewareSynthesizer };  
}  
