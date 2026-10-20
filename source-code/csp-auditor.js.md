/\*\*  
 \* CSPForge Pro \- Core CSP Level 3 Security Auditor Engine  
 \* Evaluates Content Security Policy directives against W3C standards and OWASP Top 10 recommendations.  
 \*/

class CspAuditor {  
  constructor(policyInput) {  
    if (typeof policyInput \=== 'string') {  
      this.rawPolicy \= policyInput.trim();  
      this.directives \= this.parsePolicyString(this.rawPolicy);  
    } else if (typeof policyInput \=== 'object' && policyInput \!== null) {  
      this.directives \= policyInput.directives || policyInput;  
      this.rawPolicy \= this.serializeDirectives(this.directives);  
    } else {  
      this.rawPolicy \= "";  
      this.directives \= {};  
    }  
  }

  parsePolicyString(str) {  
    const map \= {};  
    if (\!str) return map;

    const parts \= str.split(';').map(p \=\> p.trim()).filter(Boolean);  
    for (const part of parts) {  
      const tokens \= part.split(/\\s+/).filter(Boolean);  
      if (tokens.length \> 0\) {  
        const dirName \= tokens\[0\].toLowerCase();  
        const sources \= tokens.slice(1);  
        map\[dirName\] \= sources;  
      }  
    }  
    return map;  
  }

  serializeDirectives(dirs) {  
    const parts \= \[\];  
    for (const \[key, values\] of Object.entries(dirs)) {  
      if (Array.isArray(values) && values.length \> 0\) {  
        parts.push(\`\${key} \${values.join(' ')}\`);  
      } else if (typeof values \=== 'string' && values.trim()) {  
        parts.push(\`\${key} \${values.trim()}\`);  
      } else if (values \=== true) {  
        parts.push(key);  
      }  
    }  
    return parts.join('; ');  
  }

  audit() {  
    const findings \= \[\];  
    const passed \= \[\];  
    let score \= 100;

    const dirs \= this.directives;

    // Helper: get directive sources or fallback to default-src  
    const getEffectiveSources \= (name) \=\> {  
      if (dirs\[name\] && Array.isArray(dirs\[name\])) return dirs\[name\];  
      if (dirs\['default-src'\] && Array.isArray(dirs\['default-src'\])) return dirs\['default-src'\];  
      return \[\];  
    };

    const scriptSources \= getEffectiveSources('script-src');  
    const defaultSources \= dirs\['default-src'\] || \[\];

    const hasNonce \= scriptSources.some(s \=\> s.startsWith("'nonce-"));  
    const hasHash \= scriptSources.some(s \=\> s.startsWith("'sha256-") || s.startsWith("'sha384-") || s.startsWith("'sha512-"));  
    const hasStrictDynamic \= scriptSources.includes("'strict-dynamic'");

    // Check 1: Unsafe Inline Scripts without Nonce/Hash  
    const hasUnsafeInline \= scriptSources.includes("'unsafe-inline'");  
    if (hasUnsafeInline && \!hasNonce && \!hasHash && \!hasStrictDynamic) {  
      findings.push({  
        id: 'UNSAFE\_INLINE\_SCRIPTS',  
        severity: 'CRITICAL',  
        title: "Unsafe Inline Script Execution ('unsafe-inline')",  
        deduction: 30,  
        description: "The 'script-src' directive permits 'unsafe-inline' without a cryptographic nonce or hash. This allows injected inline \<script\> tags and event handlers (e.g. \<img onerror=...\>) to execute arbitrary code, rendering CSP ineffective against Cross-Site Scripting (XSS).",  
        remediation: "Remove 'unsafe-inline' and implement cryptographically random nonces (e.g., 'nonce-\$RANDOM') with 'strict-dynamic' for modern script loading."  
      });  
      score \-= 30;  
    } else if (hasUnsafeInline && (hasNonce || hasHash || hasStrictDynamic)) {  
      passed.push({  
        id: 'NONCE\_OVERRIDE\_INLINE',  
        title: "Strict Nonce Overrides 'unsafe-inline' (CSP Level 3)",  
        description: "Modern browsers (CSP3) ignore 'unsafe-inline' in the presence of a nonce or hash while maintaining backwards compatibility for legacy browsers."  
      });  
    } else if (\!hasUnsafeInline && scriptSources.length \> 0\) {  
      passed.push({  
        id: 'NO\_UNSAFE\_INLINE',  
        title: "No Insecure Inline Scripts Allowed",  
        description: "Inline scripts are blocked by default unless authorized by cryptographic hashes or nonces."  
      });  
    }

    // Check 2: Dangerous data: or blob: in script-src  
    const hasDataScript \= scriptSources.includes('data:');  
    const hasBlobScript \= scriptSources.includes('blob:');  
    if (hasDataScript || hasBlobScript) {  
      findings.push({  
        id: 'DATA\_OR\_BLOB\_SCRIPT',  
        severity: 'CRITICAL',  
        title: "Dangerous Scheme Allowed in script-src (data: or blob:)",  
        deduction: 25,  
        description: \`The script execution directive permits \[\${\[hasDataScript ? 'data:' : null, hasBlobScript ? 'blob:' : null\].filter(Boolean).join(', ')}\]. Attackers can easily bypass CSP by injecting \<script src="data:text/javascript,evil\_code()"\>.\`,  
        remediation: "Remove 'data:' and 'blob:' from script-src and default-src. Load scripts exclusively from trusted origins or via nonces."  
      });  
      score \-= 25;  
    } else {  
      passed.push({  
        id: 'NO\_DATA\_BLOB\_SCRIPT',  
        title: "No Execution of data: or blob: Script Schemes",  
        description: "Dangerous pseudo-schemes data: and blob: are prohibited from executing scripts."  
      });  
    }

    // Check 3: Unsafe Eval Code Execution ('unsafe-eval')  
    if (scriptSources.includes("'unsafe-eval'")) {  
      findings.push({  
        id: 'UNSAFE\_EVAL\_ALLOWED',  
        severity: 'HIGH',  
        title: "Dynamic String Evaluation Permitted ('unsafe-eval')",  
        deduction: 20,  
        description: "The policy allows 'unsafe-eval', enabling eval(), setTimeout('string'), and new Function(). This opens attack surfaces for DOM-based XSS, sandbox escapes, and client-side template injection.",  
        remediation: "Refactor code to avoid eval() and remove 'unsafe-eval' from the policy."  
      });  
      score \-= 20;  
    } else {  
      passed.push({  
        id: 'NO\_UNSAFE\_EVAL',  
        title: "Dynamic Code Evaluation Blocked",  
        description: "eval(), new Function(), and string-based setTimeout calls are strictly blocked."  
      });  
    }

    // Check 4: Missing or Insecure object-src ('none')  
    const objectSources \= dirs\['object-src'\];  
    if (\!objectSources || (Array.isArray(objectSources) && \!objectSources.includes("'none'"))) {  
      findings.push({  
        id: 'INSECURE\_OBJECT\_SRC',  
        severity: 'HIGH',  
        title: "Missing 'object-src 'none'' Lockdown",  
        deduction: 15,  
        description: "The 'object-src' directive is either missing or not set to 'none'. This allows legacy plugin execution (Flash, Java Applets, Silverlight) via \<object\>, \<embed\>, or \<applet\> tags.",  
        remediation: "Explicitly set: object-src 'none';"  
      });  
      score \-= 15;  
    } else {  
      passed.push({  
        id: 'OBJECT\_SRC\_LOCKED',  
        title: "Legacy Plugin Injection Blocked (object-src 'none')",  
        description: "Legacy \<object\> and \<embed\> plugins are completely disabled."  
      });  
    }

    // Check 5: Missing base-uri Lockdown ('self' or 'none')  
    const baseSources \= dirs\['base-uri'\];  
    if (\!baseSources || (Array.isArray(baseSources) && \!baseSources.includes("'self'") && \!baseSources.includes("'none'"))) {  
      findings.push({  
        id: 'MISSING\_BASE\_URI',  
        severity: 'HIGH',  
        title: "Missing or Insecure 'base-uri' Directive",  
        deduction: 15,  
        description: "The 'base-uri' directive restricts the URLs that can appear in a document's \<base\> element. Without it, an attacker can inject \<base href='https\://evil.com/'\> to hijack all relative script and asset links.",  
        remediation: "Set: base-uri 'self'; or base-uri 'none';"  
      });  
      score \-= 15;  
    } else {  
      passed.push({  
        id: 'BASE\_URI\_PROTECTED',  
        title: "Base URL Hijacking Protection (base-uri)",  
        description: "Document \<base\> tag is restricted to trusted origins, preventing relative path manipulation."  
      });  
    }

    // Check 6: Missing Clickjacking Defense (frame-ancestors)  
    const frameAncestors \= dirs\['frame-ancestors'\];  
    if (\!frameAncestors || (Array.isArray(frameAncestors) && (frameAncestors.includes('\*') || frameAncestors.length \=== 0))) {  
      findings.push({  
        id: 'MISSING\_FRAME\_ANCESTORS',  
        severity: 'HIGH',  
        title: "Missing 'frame-ancestors' Clickjacking Defense",  
        deduction: 15,  
        description: "The 'frame-ancestors' directive supersedes legacy X-Frame-Options. Without it, malicious websites can embed your application inside an invisible \<iframe\> for clickjacking and UI redressing attacks.",  
        remediation: "Set: frame-ancestors 'none'; (if never framed) or frame-ancestors 'self'; (for same-origin framing)."  
      });  
      score \-= 15;  
    } else {  
      passed.push({  
        id: 'CLICKJACKING\_PROTECTED',  
        title: "Clickjacking Defense Enforced (frame-ancestors)",  
        description: \`Framing is strictly controlled: \[\${frameAncestors.join(' ')}\].\`  
      });  
    }

    // Check 7: Overly Permissive Script Whitelist (\* or https:)  
    const hasWildcardScript \= scriptSources.includes('\*') || scriptSources.includes('https:') || scriptSources.includes('http:');  
    if (hasWildcardScript && \!hasStrictDynamic) {  
      findings.push({  
        id: 'WILDCARD\_SCRIPT\_WHITELIST',  
        severity: 'MEDIUM',  
        title: "Wildcard or Broad Protocol in script-src (\* or https:)",  
        deduction: 15,  
        description: "Allowing '\*' or 'https:' in script-src permits scripts from any website on the internet or any public cloud/CDN hosting malicious code.",  
        remediation: "Specify explicit trusted domains or adopt a nonce-based policy with 'strict-dynamic'."  
      });  
      score \-= 15;  
    } else if (hasWildcardScript && hasStrictDynamic) {  
      passed.push({  
        id: 'STRICT\_DYNAMIC\_OVERRIDE\_HOSTS',  
        title: "'strict-dynamic' Overrides Host Whitelists",  
        description: "Host whitelists are ignored by modern browsers in favor of cryptographic nonces."  
      });  
    } else {  
      passed.push({  
        id: 'CONTROLLED\_SCRIPT\_ORIGINS',  
        title: "Controlled Script Sources",  
        description: "No generic wildcards (\* or https:) allowed without strict-dynamic."  
      });  
    }

    // Check 8: Missing default-src Fallback  
    if (\!dirs\['default-src'\] || dirs\['default-src'\].length \=== 0\) {  
      findings.push({  
        id: 'MISSING\_DEFAULT\_SRC',  
        severity: 'MEDIUM',  
        title: "Missing 'default-src' Fallback Directive",  
        deduction: 10,  
        description: "Without 'default-src', directives that are not explicitly defined (such as connect-src, font-src, media-src) default to unrestricted (\*), potentially allowing data exfiltration via WebSockets or fetch().",  
        remediation: "Define a restrictive baseline: default-src 'self';"  
      });  
      score \-= 10;  
    } else {  
      passed.push({  
        id: 'DEFAULT\_SRC\_PRESENT',  
        title: "Default Fallback Defined (default-src)",  
        description: \`Unspecified resource types safely inherit from default-src: \[\${dirs\['default-src'\].join(' ')}\].\`  
      });  
    }

    // Check 9: Missing form-action Restriction  
    const formAction \= dirs\['form-action'\];  
    if (\!formAction || (Array.isArray(formAction) && formAction.includes('\*'))) {  
      findings.push({  
        id: 'MISSING\_FORM\_ACTION',  
        severity: 'LOW',  
        title: "Missing 'form-action' Target Restriction",  
        deduction: 5,  
        description: "Without 'form-action', HTML forms can be altered or submitted to any arbitrary third-party domain, enabling credential harvesting and phishing.",  
        remediation: "Set: form-action 'self';"  
      });  
      score \-= 5;  
    } else {  
      passed.push({  
        id: 'FORM\_ACTION\_RESTRICTED',  
        title: "Form Submission Targets Controlled",  
        description: \`Form submissions are restricted to: \[\${formAction.join(' ')}\].\`  
      });  
    }

    // Check 10: Insecure HTTP Sources or Missing upgrade-insecure-requests  
    const allSources \= Object.values(dirs).flat().filter(s \=\> typeof s \=== 'string');  
    const hasHttpSources \= allSources.some(s \=\> s.startsWith('http\://') && \!s.includes('localhost') && \!s.includes('127.0.0.1'));  
    const hasUpgrade \= 'upgrade-insecure-requests' in dirs;

    if (hasHttpSources) {  
      findings.push({  
        id: 'INSECURE\_HTTP\_SOURCES',  
        severity: 'LOW',  
        title: "Plaintext HTTP Sources in Policy",  
        deduction: 5,  
        description: "Policy explicitly permits unencrypted http\:// resources, creating mixed-content vulnerability vectors.",  
        remediation: "Change http\:// sources to https\:// and include 'upgrade-insecure-requests;'."  
      });  
      score \-= 5;  
    } else if (\!hasUpgrade) {  
      findings.push({  
        id: 'MISSING\_UPGRADE\_INSECURE',  
        severity: 'LOW',  
        title: "Missing 'upgrade-insecure-requests' Directive",  
        deduction: 5,  
        description: "The 'upgrade-insecure-requests' directive instructs user agents to treat all insecure HTTP URLs as HTTPS before fetching.",  
        remediation: "Add directive: upgrade-insecure-requests;"  
      });  
      score \-= 5;  
    } else {  
      passed.push({  
        id: 'HTTPS\_UPGRADE\_ENFORCED',  
        title: "HTTPS Mixed Content Protection",  
        description: "upgrade-insecure-requests ensures all legacy HTTP requests are upgraded to HTTPS."  
      });  
    }

    score \= Math.max(0, Math.min(100, score));

    let grade \= 'F';  
    let status \= 'Critical Vulnerability';  
    if (score \>= 95\) { grade \= 'A+'; status \= 'Production Hardened'; }  
    else if (score \>= 85\) { grade \= 'A'; status \= 'Secure'; }  
    else if (score \>= 75\) { grade \= 'B'; status \= 'Moderate Risk'; }  
    else if (score \>= 60\) { grade \= 'C'; status \= 'Elevated Risk'; }  
    else if (score \>= 40\) { grade \= 'D'; status \= 'High Risk'; }

    return {  
      score,  
      grade,  
      status,  
      timestamp: new Date().toISOString(),  
      rawPolicy: this.rawPolicy,  
      findingsCount: findings.length,  
      passedCount: passed.length,  
      findings,  
      passed,  
      summary: {  
        critical: findings.filter(f \=\> f.severity \=== 'CRITICAL').length,  
        high: findings.filter(f \=\> f.severity \=== 'HIGH').length,  
        medium: findings.filter(f \=\> f.severity \=== 'MEDIUM').length,  
        low: findings.filter(f \=\> f.severity \=== 'LOW').length  
      }  
    };  
  }  
}

if (typeof module \!== 'undefined' && module.exports) {  
  module.exports \= { CspAuditor };  
}  
