/\*\*  
 \* CSPForge Pro \- W3C CSP Violation & Threat Simulator Engine  
 \* Simulates browser security decisions and generates standard W3C csp-report payloads.  
 \*/

class ViolationSimulator {  
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

  getEffective(dirName) {  
    if (this.directives\[dirName\] && this.directives\[dirName\].length \> 0\) {  
      return { dir: dirName, sources: this.directives\[dirName\] };  
    }  
    if (this.directives\['default-src'\] && this.directives\['default-src'\].length \> 0\) {  
      return { dir: 'default-src', sources: this.directives\['default-src'\] };  
    }  
    return { dir: dirName, sources: \['\*'\] }; // default fallback if no default-src  
  }

  simulate(vector) {  
    const type \= vector.type || 'inline-script'; // 'inline-script', 'eval-code', 'remote-script', 'inline-style', 'legacy-plugin', 'iframe-embed', 'form-hijack'  
    const payload \= vector.payload || "";  
    const origin \= vector.origin || "https\://app.example.com";  
    const documentUri \= vector.documentUri || \`\${origin}/dashboard\`;  
    const nonce \= vector.nonce || null;

    let allowed \= false;  
    let violatedDirective \= "";  
    let effectiveDirective \= "";  
    let reason \= "";  
    let blockedUri \= "";

    switch (type) {  
      case 'inline-script': {  
        effectiveDirective \= 'script-src';  
        const eff \= this.getEffective('script-src');  
        violatedDirective \= \`\${eff.dir} \${eff.sources.join(' ')}\`;  
        blockedUri \= "inline";

        const hasStrictDynamic \= eff.sources.includes("'strict-dynamic'");  
        const hasMatchingNonce \= nonce && eff.sources.includes(\`'nonce-\${nonce}'\`);  
        const hasUnsafeInline \= eff.sources.includes("'unsafe-inline'");

        if (hasMatchingNonce) {  
          allowed \= true;  
          reason \= \`Allowed by matching cryptographic nonce ('nonce-\${nonce}').\`;  
        } else if (hasUnsafeInline && \!hasStrictDynamic && \!eff.sources.some(s \=\> s.startsWith("'nonce-"))) {  
          allowed \= true;  
          reason \= "Allowed by insecure 'unsafe-inline' directive (High XSS Risk).";  
        } else {  
          allowed \= false;  
          reason \= "Blocked: Inline scripts require a valid cryptographic nonce or hash when 'unsafe-inline' is absent or superseded by CSP3 nonces.";  
        }  
        break;  
      }

      case 'eval-code': {  
        effectiveDirective \= 'script-src';  
        const eff \= this.getEffective('script-src');  
        violatedDirective \= \`\${eff.dir} \${eff.sources.join(' ')}\`;  
        blockedUri \= "eval";

        if (eff.sources.includes("'unsafe-eval'")) {  
          allowed \= true;  
          reason \= "Allowed by 'unsafe-eval' directive (Dangerous: permits string-to-code execution).";  
        } else {  
          allowed \= false;  
          reason \= "Blocked: eval(), new Function(), and string-based setTimeout are prohibited by policy.";  
        }  
        break;  
      }

      case 'remote-script': {  
        effectiveDirective \= 'script-src';  
        const eff \= this.getEffective('script-src');  
        violatedDirective \= \`\${eff.dir} \${eff.sources.join(' ')}\`;  
        blockedUri \= payload || "https\://cdn.malicious.com/payload.js";

        const targetUrl \= new URL(blockedUri);  
        const targetHost \= targetUrl.host;

        if (eff.sources.includes('\*')) {  
          allowed \= true;  
          reason \= "Allowed by wildcard (\*) host source.";  
        } else if (eff.sources.includes("'self'") && targetUrl.origin \=== origin) {  
          allowed \= true;  
          reason \= "Allowed by same-origin ('self') matching.";  
        } else if (eff.sources.some(s \=\> s \=== targetHost || s \=== targetUrl.origin || s \=== \`https\://\${targetHost}\`)) {  
          allowed \= true;  
          reason \= \`Allowed: Host '\${targetHost}' is in script-src allowlist.\`;  
        } else if (nonce && eff.sources.includes(\`'nonce-\${nonce}'\`) && eff.sources.includes("'strict-dynamic'")) {  
          allowed \= true;  
          reason \= "Allowed via 'strict-dynamic' propagation from nonced parent script.";  
        } else {  
          allowed \= false;  
          reason \= \`Blocked: Script host '\${targetHost}' is not trusted by policy.\`;  
        }  
        break;  
      }

      case 'inline-style': {  
        effectiveDirective \= 'style-src';  
        const eff \= this.getEffective('style-src');  
        violatedDirective \= \`\${eff.dir} \${eff.sources.join(' ')}\`;  
        blockedUri \= "inline";

        if (eff.sources.includes("'unsafe-inline'")) {  
          allowed \= true;  
          reason \= "Allowed by 'style-src: unsafe-inline'.";  
        } else if (nonce && eff.sources.includes(\`'nonce-\${nonce}'\`)) {  
          allowed \= true;  
          reason \= \`Allowed by style nonce ('nonce-\${nonce}').\`;  
        } else {  
          allowed \= false;  
          reason \= "Blocked: Inline styles (\<style\> or style='...') blocked without 'unsafe-inline' or nonce.";  
        }  
        break;  
      }

      case 'legacy-plugin': {  
        effectiveDirective \= 'object-src';  
        const eff \= this.directives\['object-src'\]   
          ? { dir: 'object-src', sources: this.directives\['object-src'\] }  
          : this.getEffective('object-src');  
        violatedDirective \= \`\${eff.dir} \${eff.sources.join(' ')}\`;  
        blockedUri \= payload || "https\://attacker.com/exploit.swf";

        if (eff.sources.includes("'none'")) {  
          allowed \= false;  
          reason \= "Blocked: Legacy object/embed plugins explicitly disabled by object-src 'none'.";  
        } else {  
          allowed \= true;  
          reason \= "Allowed: Missing object-src 'none' lockdown (Plugin Exploit Risk).";  
        }  
        break;  
      }

      case 'iframe-embed': {  
        effectiveDirective \= 'frame-ancestors';  
        const sources \= this.directives\['frame-ancestors'\] || \[\];  
        violatedDirective \= \`frame-ancestors \${sources.join(' ')}\`;  
        blockedUri \= payload || "https\://attacker-site.com";

        if (sources.includes("'none'")) {  
          allowed \= false;  
          reason \= "Blocked: Embedding prohibited everywhere by frame-ancestors 'none'.";  
        } else if (sources.includes("'self'") && blockedUri.startsWith(origin)) {  
          allowed \= true;  
          reason \= "Allowed: Framed by same origin ('self').";  
        } else if (sources.includes('\*')) {  
          allowed \= true;  
          reason \= "Allowed: frame-ancestors is wildcard (\*) (Clickjacking Risk).";  
        } else if (sources.length \=== 0\) {  
          allowed \= true;  
          reason \= "Allowed: Missing frame-ancestors (Clickjacking / UI Redressing Risk).";  
        } else {  
          allowed \= false;  
          reason \= \`Blocked: Parent origin '\${blockedUri}' not authorized in frame-ancestors.\`;  
        }  
        break;  
      }

      case 'form-hijack': {  
        effectiveDirective \= 'form-action';  
        const sources \= this.directives\['form-action'\] || \[\];  
        violatedDirective \= \`form-action \${sources.join(' ')}\`;  
        blockedUri \= payload || "https\://phishing-catcher.com/login";

        if (sources.length \=== 0 || sources.includes('\*')) {  
          allowed \= true;  
          reason \= "Allowed: form-action is unrestricted or missing (Phishing Redirection Risk).";  
        } else if (sources.includes("'self'") && blockedUri.startsWith(origin)) {  
          allowed \= true;  
          reason \= "Allowed: Form posts to same-origin endpoint.";  
        } else if (sources.some(s \=\> blockedUri.startsWith(s))) {  
          allowed \= true;  
          reason \= \`Allowed: Target form action in allowlist \[\${sources.join(' ')}\].\`;  
        } else {  
          allowed \= false;  
          reason \= \`Blocked: Form submission to '\${blockedUri}' prohibited by form-action.\`;  
        }  
        break;  
      }

      default:  
        allowed \= false;  
        reason \= "Unknown threat vector type.";  
    }

    const reportPayload \= \!allowed ? {  
      "csp-report": {  
        "document-uri": documentUri,  
        "referrer": "",  
        "violated-directive": violatedDirective,  
        "effective-directive": effectiveDirective,  
        "original-policy": this.rawPolicy,  
        "disposition": "enforce",  
        "blocked-uri": blockedUri,  
        "line-number": Math.floor(Math.random() \* 80\) \+ 1,  
        "column-number": Math.floor(Math.random() \* 40\) \+ 1,  
        "source-file": documentUri,  
        "status-code": 200,  
        "script-sample": payload.substring(0, 40\)  
      }  
    } : null;

    return {  
      status: allowed ? "ALLOWED" : "BLOCKED",  
      threatType: type,  
      effectiveDirective,  
      violatedDirective,  
      blockedUri,  
      reason,  
      reportPayload  
    };  
  }  
}

if (typeof module \!== 'undefined' && module.exports) {  
  module.exports \= { ViolationSimulator };  
}  
