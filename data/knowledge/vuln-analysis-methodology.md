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

## Semantic Investigation Strategies (Beyond Pattern Matching)

These vulnerability classes CANNOT be found by matching API names. They require reasoning about program behavior.

### Resource Leaks (CWE-401, CWE-775, CWE-772)
**Investigation approach:** For every allocation call (malloc, calloc, open, socket, fopen), trace ALL exit paths from the containing function. If ANY path returns without freeing/closing the resource, it is a leak. Error-handling branches (early returns after failed checks) are the most common leak sites.
- Graph query: `get_callees("<function>")` to check if free/close is called
- Look for: `if (error) return;` between allocation and cleanup
- Common missed pattern: goto-based cleanup where a label is skipped

### Race Conditions (CWE-362, CWE-364, CWE-366, CWE-367)
**Investigation approach:** This is a STRUCTURAL vulnerability, not a single bad call.
1. Signal races (CWE-364): Find `signal()` handler installation, then check if code between signal-capable regions uses non-atomic operations (free+NULL, check+use).
2. Thread races (CWE-366): Find `pthread_create`/`CreateThread`, identify shared globals, check if ANY access is without a lock.
3. TOCTOU (CWE-367): Find `access()`/`stat()` followed by `open()`/`fopen()` on the same path — the file could change between check and use.
- These require reading MULTIPLE functions and understanding their execution relationship.

### Integer Issues Without Obvious Arithmetic (CWE-190, CWE-191, CWE-680)
**Investigation approach:** The overflow may not be `a + b` — it could be:
- Implicit truncation: `int x = (int)long_value;` — silent data loss
- Multiplication for allocation: `malloc(count * sizeof(T))` — overflow in size calc
- Subtraction underflow: `unsigned size = input - header_len;` — wraps to huge value
- Array index from narrowed type: `char index = large_value; array[index]` — wraps around
- Look for: external input → type conversion or arithmetic → use as size, index, or loop bound

### Command Injection Through Indirection (CWE-78)
**Investigation approach:** Not all command injection is `system(user_input)`.
- Spawn family: `_spawnv`, `execlp` etc. — user input may be in argv[2], not the command
- Environment modification: `putenv("PATH=...")` followed by `system("cmd")` — attacker controls search path
- File-based: User writes to a script file, then `system("./script.sh")` executes it
- Use `get_data_sources()` to find all external inputs, then `get_taint_paths()` to check if ANY reach an execution function in ANY argument position

### Trust Boundary Violations (CWE-501)
**Investigation approach:** This is about WHERE untrusted data gets stored, not what API is called.
- Session storage: `request.getParameter()` → `session.setAttribute(name, value)` — either name or value from untrusted source
- Cookie-sourced: `request.getCookies()` → decode → `session.setAttribute()`
- Header-sourced: `request.getHeader()` → `session.setAttribute()`
- The violation is storing untrusted data in a trusted context without validation
