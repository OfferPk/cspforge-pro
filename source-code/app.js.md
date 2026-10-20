/\*\*  
 \* CSPForge Pro \- Studio Web Application Controller  
 \*/

const PRESETS \= {  
  "enterprise-banking-saas": {  
    name: "Enterprise Banking SaaS (CSP Level 3 Nonce-Based)",  
    policy: "default-src 'self'; script-src 'self' 'nonce-rAnd0mB4nk1ngN0nc3' 'strict-dynamic' https: 'unsafe-inline'; style-src 'self' 'nonce-rAnd0mB4nk1ngN0nc3' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https\://api.bankcorp.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;",  
    sample\_threat: {  
      type: "inline-script",  
      payload: "\<script\>alert('XSS Steal Session')\</script\>",  
      origin: "https\://app.bankcorp.com",  
      nonce: ""  
    }  
  },  
  "vulnerable-legacy-webapp": {  
    name: "Vulnerable Legacy WebApp (Anti-Pattern Disaster)",  
    policy: "script-src 'unsafe-inline' 'unsafe-eval' data: \*; style-src \* 'unsafe-inline'; img-src \*; connect-src http\://insecure-cdn.com;",  
    sample\_threat: {  
      type: "inline-script",  
      payload: "\<script\>eval('exfiltrate\_cookies()')\</script\>",  
      origin: "https\://vulnerable-store.com",  
      nonce: ""  
    }  
  },  
  "modern-jamstack-static": {  
    name: "Modern JAMstack / Static Site (Self-Contained)",  
    policy: "default-src 'self'; script-src 'self'; style-src 'self' https\://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https\://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;",  
    sample\_threat: {  
      type: "remote-script",  
      payload: "https\://malicious-cdn.com/keylogger.js",  
      origin: "https\://mystaticsite.com",  
      nonce: ""  
    }  
  }  
};

let currentPolicy \= PRESETS\["enterprise-banking-saas"\].policy;  
let currentFramework \= 'nextjs';

document.addEventListener('DOMContentLoaded', () \=\> {  
  initTabs();  
  initPresetSelector();  
  initAuditor();  
  initSimulator();  
  initMiddleware();  
  initConfigEditor();  
  loadPreset('enterprise-banking-saas');  
});

// Tab Routing  
function initTabs() {  
  const tabs \= document.querySelectorAll('.tab-btn');  
  tabs.forEach(tab \=\> {  
    tab.addEventListener('click', () \=\> {  
      tabs.forEach(t \=\> t.classList.remove('active'));  
      document.querySelectorAll('.tab-content').forEach(c \=\> c.classList.remove('active'));

      tab.classList.add('active');  
      const targetId \= tab.getAttribute('data-tab');  
      const targetEl \= document.getElementById(targetId);  
      if (targetEl) targetEl.classList.add('active');

      if (targetId \=== 'tab-auditor') renderAuditor();  
      if (targetId \=== 'tab-simulator') runSimulator();  
      if (targetId \=== 'tab-middleware') renderMiddleware();  
      if (targetId \=== 'tab-config') syncPolicyToEditor();  
    });  
  });  
}

function initPresetSelector() {  
  const select \= document.getElementById('presetSelect');  
  select.addEventListener('change', (e) \=\> {  
    const val \= e.target.value;  
    if (PRESETS\[val\]) {  
      loadPreset(val);  
    }  
  });

  document.getElementById('btnExportPolicy').addEventListener('click', exportPolicy);  
  document.getElementById('btnDownloadZip').addEventListener('click', () \=\> {  
    alert('CSPForge Pro distribution package is located in /build/cspforge-pro-v1.0.0.zip. Use the Google Drive download link.');  
  });  
  document.getElementById('btnAutoHardenTop').addEventListener('click', autoHarden);  
}

function loadPreset(key) {  
  const p \= PRESETS\[key\];  
  if (\!p) return;  
  currentPolicy \= p.policy;

  if (p.sample\_threat) {  
    document.getElementById('simThreatType').value \= p.sample\_threat.type;  
    document.getElementById('simPayload').value \= p.sample\_threat.payload;  
    document.getElementById('simOrigin').value \= p.sample\_threat.origin;  
    document.getElementById('simNonce').value \= p.sample\_threat.nonce || '';  
  }

  syncPolicyToEditor();  
  renderAuditor();  
  runSimulator();  
  renderMiddleware();  
}

function exportPolicy() {  
  const auditor \= new CspAuditor(currentPolicy);  
  const data \= {  
    name: "Custom CSP Policy",  
    policy: currentPolicy,  
    directives: auditor.directives,  
    auditResult: auditor.audit()  
  };  
  const dataStr \= "data:text/json;charset=utf-8," \+ encodeURIComponent(JSON.stringify(data, null, 2));  
  const a \= document.createElement('a');  
  a.setAttribute("href", dataStr);  
  a.setAttribute("download", "csp-policy.json");  
  document.body.appendChild(a);  
  a.click();  
  a.remove();  
}

// Auditor Logic  
function initAuditor() {  
  document.getElementById('btnReAudit').addEventListener('click', renderAuditor);  
  document.getElementById('btnAutoHarden').addEventListener('click', autoHarden);  
}

function autoHarden() {  
  currentPolicy \= "default-src 'self'; script-src 'self' 'nonce-rAnd0mSecur3N0nce' 'strict-dynamic' https: 'unsafe-inline'; style-src 'self' 'nonce-rAnd0mSecur3N0nce' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;";  
  document.getElementById('presetSelect').value \= 'custom';  
  syncPolicyToEditor();  
  renderAuditor();  
  runSimulator();  
  renderMiddleware();  
  alert('Policy auto-hardened to strict CSP Level 3 enterprise standards\!');  
}

function renderAuditor() {  
  const auditor \= new CspAuditor(currentPolicy);  
  const res \= auditor.audit();

  // Score & Grade  
  const scoreVal \= document.getElementById('scoreVal');  
  const scoreCircle \= document.getElementById('scoreCircle');  
  const gradeBadge \= document.getElementById('gradeBadge');  
  const statusText \= document.getElementById('statusText');

  scoreVal.textContent \= res.score;  
  gradeBadge.textContent \= res.grade;  
  statusText.textContent \= res.status;

  gradeBadge.className \= 'grade-badge grade-' \+ res.grade.replace('+', '-plus');

  let circleColor \= 'var(--accent-emerald)';  
  if (res.score \< 60\) circleColor \= 'var(--accent-rose)';  
  else if (res.score \< 80\) circleColor \= 'var(--accent-amber)';  
  scoreCircle.style.borderColor \= circleColor;

  document.getElementById('critCount').textContent \= res.summary.critical;  
  document.getElementById('highCount').textContent \= res.summary.high;  
  document.getElementById('medCount').textContent \= res.summary.medium;  
  document.getElementById('lowCount').textContent \= res.summary.low;

  // Active Policy Info  
  const scriptSources \= auditor.directives\['script-src'\] || auditor.directives\['default-src'\] || \[\];  
  const hasNonce \= scriptSources.some(s \=\> s.startsWith("'nonce-"));  
  const hasStrict \= scriptSources.includes("'strict-dynamic'");

  let scriptModel \= "Host Whitelist Only";  
  if (hasNonce && hasStrict) scriptModel \= "Cryptographic Nonce \+ strict-dynamic";  
  else if (hasNonce) scriptModel \= "Cryptographic Nonce";  
  else if (scriptSources.includes("'unsafe-inline'")) scriptModel \= "Insecure 'unsafe-inline' (Critical Risk)";  
  document.getElementById('infoScriptModel').textContent \= scriptModel;

  const evalAllowed \= scriptSources.includes("'unsafe-eval'");  
  document.getElementById('infoEval').textContent \= evalAllowed ? "Allowed (High Risk)" : "Blocked";  
  document.getElementById('infoEval').style.color \= evalAllowed ? "var(--accent-rose)" : "var(--accent-emerald)";

  const objSources \= auditor.directives\['object-src'\] || \[\];  
  const objBlocked \= objSources.includes("'none'");  
  document.getElementById('infoObject').textContent \= objBlocked ? "'none' (Secure)" : "Missing / Insecure";  
  document.getElementById('infoObject').style.color \= objBlocked ? "var(--accent-emerald)" : "var(--accent-rose)";

  const frameSources \= auditor.directives\['frame-ancestors'\] || \[\];  
  document.getElementById('infoFraming').textContent \= frameSources.length \> 0 ? frameSources.join(' ') : "Missing (Vulnerable to Clickjacking)";  
  document.getElementById('infoFraming').style.color \= frameSources.length \> 0 && \!frameSources.includes('\*') ? "var(--accent-emerald)" : "var(--accent-rose)";

  const baseSources \= auditor.directives\['base-uri'\] || \[\];  
  document.getElementById('infoBase').textContent \= baseSources.length \> 0 ? baseSources.join(' ') : "Missing (Vulnerable to Base Tag Injection)";  
  document.getElementById('infoBase').style.color \= baseSources.length \> 0 && \!baseSources.includes('\*') ? "var(--accent-emerald)" : "var(--accent-rose)";

  // Findings list  
  const findingsList \= document.getElementById('findingsList');  
  const findingsHeaderBadge \= document.getElementById('findingsHeaderBadge');  
  findingsHeaderBadge.textContent \= \`\${res.findingsCount} Issues\`;

  if (res.findings.length \=== 0\) {  
    findingsList.innerHTML \= \`\<div style="padding: 16px; text-align: center; color: var(--accent-emerald); font-weight: 600;"\>  
      ✓ Clean Bill of Health\! Zero CSP / XSS vulnerabilities detected.  
    \</div\>\`;  
  } else {  
    findingsList.innerHTML \= res.findings.map(f \=\> \`  
      \<div class="finding-card severity-\${f.severity}"\>  
        \<div class="finding-header"\>  
          \<div class="finding-title-group"\>  
            \<span class="sev-badge sev-\${f.severity}"\>\${f.severity}\</span\>  
            \<strong style="color: \#fff; font-size: 13px;"\>\${f.title}\</strong\>  
          \</div\>  
          \<span class="finding-deduction"\>-\${f.deduction} pts\</span\>  
        \</div\>  
        \<div class="finding-desc"\>\${f.description}\</div\>  
        \<div class="finding-remediation"\>\<strong\>Remediation:\</strong\> \${f.remediation}\</div\>  
      \</div\>  
    \`).join('');  
  }

  // Passed controls  
  const passedList \= document.getElementById('passedList');  
  const passedHeaderBadge \= document.getElementById('passedHeaderBadge');  
  passedHeaderBadge.textContent \= \`\${res.passedCount} Controls Verified\`;

  passedList.innerHTML \= res.passed.map(p \=\> \`  
    \<div class="passed-item"\>  
      \<span class="check-icon"\>✓\</span\>  
      \<div\>  
        \<strong style="color: \#fff;"\>\${p.title}:\</strong\>  
        \<span style="color: var(--text-secondary); margin-left: 4px;"\>\${p.description}\</span\>  
      \</div\>  
    \</div\>  
  \`).join('');  
}

// Threat Simulator Logic  
function initSimulator() {  
  document.getElementById('btnRunSim').addEventListener('click', runSimulator);  
  document.getElementById('simThreatType').addEventListener('change', (e) \=\> {  
    const type \= e.target.value;  
    if (type \=== 'inline-script') document.getElementById('simPayload').value \= "\<script\>alert('XSS Steal Cookies')\</script\>";  
    else if (type \=== 'eval-code') document.getElementById('simPayload').value \= "eval('window.exfiltrate()')";  
    else if (type \=== 'remote-script') document.getElementById('simPayload').value \= "https\://cdn.malicious.com/keylogger.js";  
    else if (type \=== 'inline-style') document.getElementById('simPayload').value \= "\<style\>body { background: url('https\://evil.com/bg'); }\</style\>";  
    else if (type \=== 'legacy-plugin') document.getElementById('simPayload').value \= "https\://evil.com/flash\_exploit.swf";  
    else if (type \=== 'iframe-embed') document.getElementById('simPayload').value \= "https\://phishing-site.com";  
    else if (type \=== 'form-hijack') document.getElementById('simPayload').value \= "https\://attacker.com/collect\_passwords";  
    runSimulator();  
  });  
}

function runSimulator() {  
  const type \= document.getElementById('simThreatType').value;  
  const payload \= document.getElementById('simPayload').value;  
  const nonce \= document.getElementById('simNonce').value.trim();  
  const origin \= document.getElementById('simOrigin').value.trim();

  const sim \= new ViolationSimulator(currentPolicy);  
  const res \= sim.simulate({  
    type,  
    payload,  
    origin,  
    nonce  
  });

  const box \= document.getElementById('simVerdictBox');  
  const title \= document.getElementById('simVerdictTitle');  
  const desc \= document.getElementById('simVerdictDesc');

  box.className \= 'sim-verdict-box verdict-' \+ res.status;  
  title.textContent \= res.status;  
  if (res.status \=== 'BLOCKED') {  
    desc.textContent \= "Browser terminated execution. XSS threat mitigated by CSP Level 3 policy.";  
  } else {  
    desc.textContent \= "Execution permitted by active policy. Potential vulnerability exposed\!";  
  }

  document.getElementById('simReason').textContent \= res.reason;

  const reportPre \= document.getElementById('simReportJson');  
  if (res.reportPayload) {  
    reportPre.textContent \= JSON.stringify(res.reportPayload, null, 2);  
  } else {  
    reportPre.textContent \= "// No violation report triggered: Operation was permitted by policy.";  
  }  
}

// Middleware Synthesizer Logic  
function initMiddleware() {  
  const btns \= document.querySelectorAll('.sub-tab-btn');  
  btns.forEach(btn \=\> {  
    btn.addEventListener('click', () \=\> {  
      btns.forEach(b \=\> b.classList.remove('active'));  
      btn.classList.add('active');  
      currentFramework \= btn.getAttribute('data-framework');  
      renderMiddleware();  
    });  
  });

  document.getElementById('btnCopyCode').addEventListener('click', () \=\> {  
    const code \= document.getElementById('middlewareCodeBlock').textContent;  
    navigator.clipboard.writeText(code).then(() \=\> {  
      alert('Middleware code copied to clipboard\!');  
    });  
  });  
}

function renderMiddleware() {  
  const synth \= new MiddlewareSynthesizer(currentPolicy);  
  let code \= '';  
  if (currentFramework \=== 'nextjs') code \= synth.generateNextJS();  
  else if (currentFramework \=== 'express') code \= synth.generateExpress();  
  else if (currentFramework \=== 'fastapi') code \= synth.generateFastAPI();  
  else if (currentFramework \=== 'nginx') code \= synth.generateNginx();  
  else if (currentFramework \=== 'apache') code \= synth.generateApache();  
  else if (currentFramework \=== 'meta') code \= synth.generateMetaTag();

  document.getElementById('middlewareCodeBlock').textContent \= code;  
}

// Policy Editor Logic  
function initConfigEditor() {  
  document.getElementById('btnApplyVisual').addEventListener('click', applyVisualDirectives);  
  document.getElementById('btnApplyRaw').addEventListener('click', applyRawPolicy);  
}

function syncPolicyToEditor() {  
  const auditor \= new CspAuditor(currentPolicy);  
  const dirs \= auditor.directives;

  document.getElementById('dirDefault').value \= (dirs\['default-src'\] || \[\]).join(' ');  
  document.getElementById('dirScript').value \= (dirs\['script-src'\] || \[\]).join(' ');  
  document.getElementById('dirStyle').value \= (dirs\['style-src'\] || \[\]).join(' ');  
  document.getElementById('dirImg').value \= (dirs\['img-src'\] || \[\]).join(' ');  
  document.getElementById('dirConnect').value \= (dirs\['connect-src'\] || \[\]).join(' ');  
  document.getElementById('dirObject').value \= (dirs\['object-src'\] || \[\]).join(' ');  
  document.getElementById('dirBase').value \= (dirs\['base-uri'\] || \[\]).join(' ');  
  document.getElementById('dirForm').value \= (dirs\['form-action'\] || \[\]).join(' ');  
  document.getElementById('dirFrame').value \= (dirs\['frame-ancestors'\] || \[\]).join(' ');

  document.getElementById('rawPolicyEditor').value \= currentPolicy;  
}

function applyVisualDirectives() {  
  const parts \= \[\];  
  const fields \= \[  
    { id: 'dirDefault', name: 'default-src' },  
    { id: 'dirScript', name: 'script-src' },  
    { id: 'dirStyle', name: 'style-src' },  
    { id: 'dirImg', name: 'img-src' },  
    { id: 'dirConnect', name: 'connect-src' },  
    { id: 'dirObject', name: 'object-src' },  
    { id: 'dirBase', name: 'base-uri' },  
    { id: 'dirForm', name: 'form-action' },  
    { id: 'dirFrame', name: 'frame-ancestors' }  
  \];

  fields.forEach(f \=\> {  
    const val \= document.getElementById(f.id).value.trim();  
    if (val) {  
      parts.push(\`\${f.name} \${val}\`);  
    }  
  });

  parts.push("upgrade-insecure-requests");  
  currentPolicy \= parts.join('; ') \+ ';';

  document.getElementById('presetSelect').value \= 'custom';  
  syncPolicyToEditor();  
  renderAuditor();  
  runSimulator();  
  renderMiddleware();  
  alert('Directives updated and policy re-scanned\!');  
}

function applyRawPolicy() {  
  const raw \= document.getElementById('rawPolicyEditor').value.trim();  
  if (\!raw) {  
    alert('Policy cannot be empty');  
    return;  
  }  
  currentPolicy \= raw;  
  document.getElementById('presetSelect').value \= 'custom';  
  syncPolicyToEditor();  
  renderAuditor();  
  runSimulator();  
  renderMiddleware();  
  alert('Raw policy synchronized and evaluated\!');  
}  
