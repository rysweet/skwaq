# Vulnerability Analysis Methodology

## 10-Step Evaluation Process

### Step 1: Initial Reconnaissance
- Identify application purpose and user interaction points
- Catalog technologies: languages, frameworks, third-party libraries
- Review architecture documentation, API specs, security models
- Classify: open-source vs proprietary, legacy vs modern

### Step 2: Attack Surface Analysis
- Map entry points: user inputs, network interfaces, APIs, file I/O
- Perform data flow analysis: trace untrusted data from sources to sinks
- Enumerate external APIs, configurable settings, privilege boundaries
- Define trust zones and sensitive data boundaries

### Step 3: Threat Modeling (STRIDE)
- **S**poofing: Can an attacker impersonate a user or component?
- **T**ampering: Can data be modified in transit or at rest?
- **R**epudiation: Can actions be denied without audit trails?
- **I**nformation disclosure: Can sensitive data leak?
- **D**enial of service: Can availability be disrupted?
- **E**levation of privilege: Can an attacker gain unauthorized access?

### Step 4: Static Code Review
- Manual review: suspicious patterns, logic flaws, hardcoded secrets
- Automated SAST: pattern detection, taint analysis, type checking
- Dependency analysis: known CVEs in third-party libraries
- Check against secure coding guidelines (OWASP, CERT)

### Step 5: Dynamic Testing
- Fuzz testing: discover crashes, memory corruption, undefined behavior
- Runtime analysis: memory leaks, use-after-free, race conditions
- Penetration testing: simulate realistic attacker scenarios
- IAST: combine static and dynamic for deeper coverage

### Step 6: Common Vulnerability Patterns

#### Memory Safety (C/C++)
- Buffer overflow (CWE-119/120/121/122): strcpy, sprintf, gets, memcpy without bounds
- Use-after-free (CWE-416): accessing memory after free()
- Double-free (CWE-415): calling free() twice on same pointer
- Integer overflow (CWE-190): arithmetic on untrusted sizes before allocation
- Format string (CWE-134): printf with user-controlled format string
- Null pointer deref (CWE-476): dereferencing without null check

#### Injection (All Languages)
- SQL injection (CWE-89): string concatenation in queries
- OS command injection (CWE-78): system(), exec(), popen() with user input
- LDAP injection (CWE-90): unsanitized LDAP filter parameters
- XSS (CWE-79): reflecting user input in HTML without encoding
- Code injection (CWE-94): eval(), exec() with untrusted code

#### Authentication & Session
- Broken authentication (CWE-287): weak password policies, credential stuffing
- Session fixation (CWE-384): predictable session tokens
- Insecure cookie (CWE-614): missing Secure/HttpOnly flags
- Trust boundary violation (CWE-501): mixing trusted and untrusted data

#### Cryptography
- Weak algorithms (CWE-327): DES, RC4, MD5, SHA-1
- Insufficient key length (CWE-326): RSA < 2048, AES < 128
- Weak PRNG (CWE-338): rand(), Math.random() for security decisions
- Hard-coded credentials (CWE-798): passwords, API keys in source code

### Step 7: Dependency & Supply Chain
- Scan dependencies for known CVEs
- Check dependency freshness and maintenance status
- Verify integrity: checksums, signed packages
- Evaluate transitive dependencies

### Step 8: Security Controls Review
- Input validation: allowlists vs denylists
- Output encoding: context-appropriate (HTML, URL, SQL, etc.)
- Authentication strength: MFA, rate limiting, account lockout
- Authorization: principle of least privilege, RBAC
- Logging: sufficient audit trail without sensitive data exposure
- Encryption: TLS 1.2+, AES-256-GCM, proper key management

### Step 9: Reporting (CVSS Scoring)
- Base score: attack vector, complexity, privileges required, user interaction
- Impact: confidentiality, integrity, availability
- Exploitability: proof of concept, active exploitation
- Prioritize by: severity × exploitability × business impact

### Step 10: Continuous Monitoring
- Regular re-assessment on code changes
- Dependency vulnerability monitoring
- Security regression testing in CI/CD
- Threat intelligence integration
