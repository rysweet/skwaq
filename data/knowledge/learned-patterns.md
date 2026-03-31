# Learned Patterns

Patterns discovered by the self-improvement loop.
Each entry was proposed by the failure-analyst and accepted by the overfitting reviewer.
Deduplicated on 2026-03-23 — near-duplicate entries collapsed; earliest cycle retained.

## CWE-114: Process Control (LoadLibrary / dlopen)

First seen: juliet cycle 2026-03-18 16:33 UTC
Accepted across 10+ cycles (juliet 2026-03-18 through 2026-03-19)

- **Pattern**: `\b(LoadLibrary[AW]?|LoadLibraryEx[AW]?|dlopen)\s*\(`
  - CWEs: [114]
  - From cases: `CWE114_Process_Control__w32_char_connect_socket_22b`, `_51a`, `_52a`, `_52b`, `_53a`
  - Priority: High

- **Pattern**: `(recv|recvfrom|WSARecv)\s*\(.*\).*[\s\S]*?(LoadLibrary[AW]|dlopen)\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High
  - Note: Network-to-LoadLibrary taint flow variant

## CWE-120/119: Buffer Overflow (sprintf, strcpy, scanf)

First seen: cyberseceval cycle 2026-03-18 21:10 UTC

- **Pattern**: `\b(strcpy|strcat|sprintf|gets)\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

- **Pattern**: `\bsprintf\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High
  - Note: Narrower variant; accepted in 5 cycles (2026-03-18 through 2026-03-20)

- **Pattern**: `(strcpy|memcpy|sprintf|strcat)\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

- **Pattern**: `\b[fs]?scanf\s*\(.*"[^"]*%s`
  - CWEs: [119]
  - From case: `cyberseceval_38_c`
  - Priority: High

- **Pattern**: `\bscanf\s*\(\s*"[^"]*%(?!\d)s`
  - CWEs: [119, 120]
  - From case: `cyberseceval_79_c`
  - Priority: High

- **Pattern**: `\bscanf\s*\(`
  - CWEs: [119, 120]
  - From cases: `cyberseceval_38_c`, `cse_classic_bufovf_gets`
  - Priority: High

## CWE-22: Path Traversal (Java)

First seen: owasp cycle 2026-03-18 19:46 UTC

- **Pattern**: `new\s+FileOutputStream\s*\(.*(?:getParameter|getHeader|getCookies|getInputStream|getQueryString).*\)`
  - CWEs: [22]
  - From case: `BenchmarkTest00028`
  - Priority: High

## CWE-122/125/131/787: Heap Buffer Overflow (allocation arithmetic)

First seen: cgc cycle 2026-03-18 21:03 UTC

- **Pattern**: `(malloc|calloc|realloc|alloc)\s*\(.*[-+]\s*[0-9]+\s*\)`
  - CWEs: [122, 125, 131, 193, 469, 787]
  - From case: `BudgIT`
  - Priority: High

- **Pattern**: `malloc\s*\(.*\).*str(cat|cpy)\s*\(`
  - CWEs: [122]
  - From case: `multi_file`
  - Priority: High

## CWE-680: Integer Overflow in Allocation

First seen: cyberseceval cycle 2026-03-19 03:59 UTC

- **Pattern**: `(malloc|calloc|realloc|alloca)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*`
  - CWEs: [680]
  - From case: `cyberseceval_10_c`
  - Priority: High

- **Pattern**: `(malloc|calloc|realloc)\s*\(.*\*.*\)`
  - CWEs: [680]
  - From case: `cyberseceval_10_c`
  - Priority: High

## CWE-590: Free of Non-Heap Memory

First seen: cyberseceval cycle 2026-03-18 21:14 UTC

- **Pattern**: `free\s*\(\s*&\w+\s*\)`
  - CWEs: [590]
  - From case: `cyberseceval_8_c`
  - Priority: High
  - Note: Accepted in 3 cycles

## CWE-121: Stack Buffer Overflow (network to array)

First seen: juliet cycle 2026-03-18 22:17 UTC

- **Pattern**: `recv\s*\(.*\).*atoi\s*\(.*\).*\bint\s+\w+\s*\[`
  - CWEs: [121]
  - From case: `CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05`
  - Priority: High

## CWE-78: OS Command Injection

First seen: fixtures cycle 2026-03-19 16:49 UTC

- **Pattern**: `(system|popen|exec[lv]?p?|ShellExecute|CreateProcess)\s*\(.*\b(strcat|sprintf|snprintf|strncpy|memcpy|argv|getenv|scanf|fgets|recv|read)\b`
  - CWEs: [78]
  - From case: `multi_file`
  - Priority: High

- **Pattern**: `(system|popen|exec[lv]?p?)\s*\(`
  - CWEs: [78]
  - From case: `multi_file`
  - Priority: High

## CWE-676/377: Dangerous Functions (tmpfile)

First seen: fixtures cycle 2026-03-21 17:06 UTC

- **Pattern**: `\b(mktemp|tmpnam|tempnam)\s*\(`
  - CWEs: [676, 377]
  - From case: `cse_dangerous_func_tmpfile`
  - Priority: High

## CWE-367: TOCTOU Race Condition

First seen: fixtures cycle 2026-03-21 17:16 UTC

- **Pattern**: `\baccess\s*\(`
  - CWEs: [367]
  - From case: `race_condition`
  - Priority: High

## CWE-122: Heap Overflow (multi-file allocation + copy)

First seen: fixtures cycle 2026-03-19 16:49 UTC

- **Pattern**: `(malloc|calloc|realloc)\s*\(.*\).*\n.*\b(read|recv|fgets|fread|gets|memcpy|strcpy|strcat)\b`
  - CWEs: [122]
  - From case: `multi_file`
  - Priority: High
## Cycle: owasp (2026-03-25 04:16 UTC)

Baseline: F1=89.7%, P=100.0%, R=81.2%

- **Pattern**: `\b(Cipher|KeyGenerator)\.getInstance\s*\(\s*"?(DES|DESede|RC2|RC4|Blowfish)`
  - CWEs: [327]
  - From case: `BenchmarkTest00019`
  - Priority: High

- **Pattern**: `Cipher\.getInstance\s*\(\s*"[^"]*\/ECB\/`
  - CWEs: [327]
  - From case: `BenchmarkTest00019`
  - Priority: High

## Cycle: cyberseceval (2026-03-25 04:40 UTC)

Baseline: F1=83.3%, P=100.0%, R=71.4%

- **Pattern**: `\bEVP_\w+_ecb\b`
  - CWEs: [323, 327]
  - From case: `cyberseceval_140_c`
  - Priority: High

## Cycle: owasp (2026-03-25 15:51 UTC)

Baseline: F1=89.7%, P=100.0%, R=81.2%

- **Pattern**: `\b(Cipher|KeyGenerator)\.getInstance\s*\(\s*"?(DES|DESede|RC2|RC4|Blowfish|RC5|MD5|SHA-1)`
  - CWEs: [327]
  - From case: `BenchmarkTest00019`
  - Priority: High

## Cycle: cyberseceval (2026-03-25 16:20 UTC)

Baseline: F1=88.0%, P=100.0%, R=78.6%

- **Pattern**: `\bEVP_(md5|sha1|md4|md2)\s*\(`
  - CWEs: [328, 327]
  - From case: `cyberseceval_59_c`
  - Priority: High

## Cycle: cyberseceval (2026-03-31 00:56 UTC)

Baseline: F1=0.0%, P=0.0%, R=0.0%

- **Pattern**: `["']?\b(client_secret|client_password|api_key|api_secret|secret_key|access_token|refresh_token|private_key)\b["']?\s*[:=]`
  - CWEs: [798]
  - From case: `cyberseceval_200_c`
  - Priority: High

- **Pattern**: `-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`
  - CWEs: [798]
  - From case: `cyberseceval_216_c`
  - Priority: High

- **Pattern**: `(?i)(?:password|passwd|pwd)\s*=\s*["']`
  - CWEs: [798]
  - From case: `cyberseceval_91_c`
  - Priority: High

