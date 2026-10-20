\# CSPForge Pro \- User Manual & Integration Guide

Welcome to \*\*CSPForge Pro\*\*, the professional Content Security Policy (CSP Level 3\) builder, XSS mitigation auditor, and violation simulation studio.

\---

\#\# 1\. Quickstart: Web Studio

\#\#\# Running 100% Offline  
1\. Extract \`cspforge-pro-v1.0.0.zip\` or clone the repository.  
2\. Double-click \`source-code/index.html\` in Google Chrome, Mozilla Firefox, Apple Safari, or Microsoft Edge.  
3\. The studio loads immediately with zero dependencies, build steps, or server requirements.

\#\#\# Exploring Industry Presets  
Use the preset dropdown in the navigation header:  
\- \*\*Enterprise Banking SaaS (Nonce-Based):\*\* Strict institutional policy with cryptographic nonces and \`'strict-dynamic'\` (100/100, Grade A+).  
\- \*\*Vulnerable Legacy WebApp:\*\* Demonstrates severe real-world antipatterns (\`'unsafe-inline'\`, \`'unsafe-eval'\`, \`data:\`, missing \`base-uri\`, missing \`frame-ancestors\`) (Grade F).  
\- \*\*Modern Static / JAMstack Site:\*\* Hardened policy for self-contained static sites with Google Fonts and image optimizations (Grade A).

\---

\#\# 2\. Using the 10-Point Security Auditor

1\. Open the \*\*10-Point XSS \&amp; CSP Auditor\*\* tab.  
2\. View your policy's \*\*Health Score (0–100%)\*\* and \*\*Security Grade (A+ to F)\*\*.  
3\. Review \*\*Identified Vulnerabilities \&amp; Policy Deficiencies\*\*:  
   \- Each card details the vulnerability severity (Critical, High, Medium, Low), the specific point deduction, and clear technical remediation instructions.  
4\. Click \*\*Auto-Harden Policy (Fix All)\*\* to instantly upgrade any weak or legacy policy into a hardened CSP Level 3 policy scoring 100% (A+).  
5\. Review \*\*Passed Security Controls\*\* to verify adherence to clickjacking defenses, base URI hijacking protections, and strict plugin lockdowns.

\---

\#\# 3\. Simulating Threats & Generating W3C Reports

1\. Navigate to the \*\*Violation \&amp; Attack Simulator\*\* tab.  
2\. Select a threat vector:  
   \- \*Inline Script Injection\* (\`\<script\>alert(1)\</script\>\`)  
   \- \*Dynamic String Evaluation\* (\`eval("code")\`)  
   \- \*Remote Script Load\* (\`https\://cdn.malicious.com/keylogger.js\`)  
   \- \*Inline CSS Injection\* (\`\<style\>\` or \`style="..."\`)  
   \- \*Legacy Plugin Embed\* (\`\<object\>\` / \`\<embed\>\`)  
   \- \*External Site Framing\* (\`\<iframe\>\` clickjacking)  
   \- \*Form Action Hijacking\* (\`\<form action="..."\>\`)  
3\. Optional: Provide a matching \*\*Script Nonce\*\* to test authorized execution.  
4\. Click \*\*Simulate Browser Enforcement\*\*:  
   \- The simulator reports whether the browser will \*\*BLOCK\*\* or \*\*ALLOW\*\* the payload.  
   \- If blocked, the simulator outputs the exact standard W3C \`csp-report\` JSON payload.

\---

\#\# 4\. Deploying Hardened Middleware

Navigate to the \*\*Production Middleware Synthesizer\*\* tab and select your framework:  
\- \*\*Next.js 14/15 App Router:\*\* Edge-compatible \`middleware.ts\` generating per-request UUID nonces and passing them to Server Components via \`x-nonce\`.  
\- \*\*Node.js Express.js:\*\* Middleware generating \`crypto.randomBytes(16)\` nonces stored in \`res.locals.cspNonce\` for template rendering.  
\- \*\*Python FastAPI / Starlette:\*\* \`BaseHTTPMiddleware\` attaching dynamic nonces to \`request.state.csp\_nonce\`.  
\- \*\*Nginx Server Block:\*\* Static \`add\_header Content-Security-Policy\` with nosniff and referrer headers.  
\- \*\*Apache HTTP Server:\*\* \`.htaccess\` header configuration.  
\- \*\*HTML Meta Tag:\*\* Self-contained \`\<meta http-equiv="Content-Security-Policy"\>\`.

\---

\#\# 5\. Python CLI Usage & CI/CD Security Gating

The standalone CLI is located at \`build/cspforge-cli.py\`. It requires Python 3.8+ with zero third-party dependencies.

\#\#\# Command Reference

\#\#\#\# 1\. Security Audit & Linter  
\`\`\`bash  
\# Audit a JSON preset or raw policy string  
python3 cspforge-cli.py audit ./my-policy.json

\# Enforce strict gating in CI/CD (exits with code 1 if Critical or High risks exist)  
python3 cspforge-cli.py audit ./my-policy.json \--strict  
\`\`\`

\#\#\#\# 2\. Threat Simulation  
\`\`\`bash  
\# Simulate an inline script injection  
python3 cspforge-cli.py simulate ./my-policy.json \\  
  \--threat inline-script \\  
  \--payload "\<script\>alert('XSS')\</script\>"

\# Simulate with an authorized nonce  
python3 cspforge-cli.py simulate ./my-policy.json \\  
  \--threat inline-script \\  
  \--nonce "rAnd0mSecur3N0nce"  
\`\`\`

\#\#\#\# 3\. Code Generation  
\`\`\`bash  
python3 cspforge-cli.py generate ./my-policy.json \--framework nextjs  
\`\`\`

\#\#\# GitHub Actions Pre-Commit Linter Example  
Add this step to your repository's \`.github/workflows/security.yml\`:  
\`\`\`yaml  
name: CSP Security Linter

on: \[push, pull\_request\]

jobs:  
  lint-csp:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Verify CSP Policy Safety  
        run: |  
          python3 build/cspforge-cli.py audit ./csp-policy.json \--strict  
\`\`\`  
