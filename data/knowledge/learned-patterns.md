# Learned Patterns

Patterns discovered by the self-improvement loop.
Each entry was proposed by the failure-analyst and accepted by the overfitting reviewer.

## Cycle: juliet (2026-03-18 16:33 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `LoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_22b`
  - Priority: High

- **Pattern**: `(recv|recvfrom|WSARecv)\s*\(.*\).*[\s\S]*?(LoadLibrary[AW]|dlopen)\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

## Cycle: juliet (2026-03-18 16:37 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `\bLoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

## Cycle: juliet (2026-03-18 16:52 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `LoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

## Cycle: juliet (2026-03-18 17:20 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `LoadLibrary[AW]\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_22b`
  - Priority: High

## Cycle: juliet (2026-03-18 19:11 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `LoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_22b`
  - Priority: High

- **Pattern**: `LoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_52a`
  - Priority: High

- **Pattern**: `\b(LoadLibrary[AW]?|dlopen)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_53a`
  - Priority: High

## Cycle: juliet (2026-03-18 19:38 UTC)

Baseline: F1=86.5%, P=100.0%, R=76.2%

- **Pattern**: `LoadLibrary[A-W]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

## Cycle: owasp (2026-03-18 19:46 UTC)

Baseline: F1=82.9%, P=85.3%, R=80.6%

- **Pattern**: `new\s+FileOutputStream\s*\(.*(?:getParameter|getHeader|getCookies|getInputStream|getQueryString).*\)`
  - CWEs: [22]
  - From case: `BenchmarkTest00028`
  - Priority: High

## Cycle: cgc (2026-03-18 21:03 UTC)

Baseline: F1=93.6%, P=100.0%, R=88.0%

- **Pattern**: `(malloc|calloc|realloc|alloc)\s*\(.*[-+]\s*[0-9]+\s*\)`
  - CWEs: [122, 125, 131, 193, 469, 787]
  - From case: `BudgIT`
  - Priority: High

## Cycle: cyberseceval (2026-03-18 21:10 UTC)

Baseline: F1=76.9%, P=100.0%, R=62.5%

- **Pattern**: `\b(strcpy|strcat|sprintf|gets)\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

## Cycle: cyberseceval (2026-03-18 21:14 UTC)

Baseline: F1=76.9%, P=100.0%, R=62.5%

- **Pattern**: `sprintf\s*\(\s*\w+\s*,`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

- **Pattern**: `free\s*\(\s*&\w+\s*\)`
  - CWEs: [590]
  - From case: `cyberseceval_8_c`
  - Priority: High

## Cycle: juliet (2026-03-18 22:17 UTC)

Baseline: F1=0.0%, P=0.0%, R=0.0%

- **Pattern**: `recv\s*\(.*\).*atoi\s*\(.*\).*\bint\s+\w+\s*\[`
  - CWEs: [121]
  - From case: `CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05`
  - Priority: High

## Cycle: cyberseceval (2026-03-19 03:59 UTC)

Baseline: F1=82.9%, P=100.0%, R=70.8%

- **Pattern**: `(malloc|calloc|realloc|alloca)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*`
  - CWEs: [680]
  - From case: `cyberseceval_10_c`
  - Priority: High

## Cycle: juliet (2026-03-19 04:04 UTC)

Baseline: F1=86.5%, P=100.0%, R=76.2%

- **Pattern**: `LoadLibrary[AW]\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

- **Pattern**: `LoadLibrary[AW]\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_52b`
  - Priority: High

## Cycle: cyberseceval (2026-03-19 04:37 UTC)

Baseline: F1=76.9%, P=100.0%, R=62.5%

- **Pattern**: `\b(strcpy|strcat|gets|sprintf)\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

## Cycle: juliet (2026-03-19 04:43 UTC)

Baseline: F1=81.5%, P=100.0%, R=68.8%

- **Pattern**: `LoadLibrary(A|W|ExA|ExW)\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_22b`
  - Priority: High

- **Pattern**: `LoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_52a`
  - Priority: High

## Cycle: cyberseceval (2026-03-19 14:37 UTC)

Baseline: F1=82.9%, P=100.0%, R=70.8%

- **Pattern**: `strcpy\s*\(\s*\w+\s*,`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

- **Pattern**: `(malloc|calloc|realloc)\s*\(.*[*+].*\)`
  - CWEs: [680]
  - From case: `cyberseceval_10_c`
  - Priority: High

## Cycle: juliet (2026-03-19 14:43 UTC)

Baseline: F1=86.5%, P=100.0%, R=76.2%

- **Pattern**: `LoadLibrary[AW]?\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

## Cycle: cyberseceval (2026-03-19 15:32 UTC)

Baseline: F1=80.6%, P=100.0%, R=67.5%

- **Pattern**: `(strcpy|memcpy|sprintf|strcat)\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

- **Pattern**: `free\s*\(\s*&\w+\s*\)`
  - CWEs: [590]
  - From case: `cyberseceval_8_c`
  - Priority: High

## Cycle: juliet (2026-03-19 15:37 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `\b(LoadLibrary[AW]|LoadLibraryEx[AW]|dlopen)\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

- **Pattern**: `LoadLibrary[AW]\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_52a`
  - Priority: High

## Cycle: cyberseceval (2026-03-19 16:29 UTC)

Baseline: F1=80.6%, P=100.0%, R=67.5%

- **Pattern**: `free\s*\(\s*&\w+\s*\)`
  - CWEs: [590]
  - From case: `cyberseceval_8_c`
  - Priority: High

- **Pattern**: `(malloc|calloc|realloc)\s*\(.*\*.*\)`
  - CWEs: [680]
  - From case: `cyberseceval_10_c`
  - Priority: High

- **Pattern**: `\bsprintf\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

## Cycle: juliet (2026-03-19 16:34 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `\b(LoadLibrary[AW]?|LoadLibraryEx[AW]?)\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_51a`
  - Priority: High

- **Pattern**: `(LoadLibrary[AW]?|dlopen)\s*\(`
  - CWEs: [114]
  - From case: `CWE114_Process_Control__w32_char_connect_socket_52a`
  - Priority: High

## Cycle: fixtures (2026-03-19 16:49 UTC)

Baseline: F1=90.5%, P=90.5%, R=90.5%

- **Pattern**: `(malloc|calloc|realloc)\s*\(.*\).*\n.*\b(read|recv|fgets|fread|gets|memcpy|strcpy|strcat)\b`
  - CWEs: [122]
  - From case: `multi_file`
  - Priority: High

- **Pattern**: `(system|popen|exec[lv]?p?|ShellExecute|CreateProcess)\s*\(.*\b(strcat|sprintf|snprintf|strncpy|memcpy|argv|getenv|scanf|fgets|recv|read)\b`
  - CWEs: [78]
  - From case: `multi_file`
  - Priority: High

## Cycle: cyberseceval (2026-03-20 05:02 UTC)

Baseline: F1=80.0%, P=100.0%, R=66.7%

- **Pattern**: `\bsprintf\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

## Cycle: cyberseceval (2026-03-20 14:07 UTC)

Baseline: F1=85.7%, P=100.0%, R=75.0%

- **Pattern**: `\bsprintf\s*\(`
  - CWEs: [120]
  - From case: `cyberseceval_7_c`
  - Priority: High

## Cycle: cyberseceval (2026-03-21 07:36 UTC)

Baseline: F1=25.0%, P=100.0%, R=14.3%

- **Pattern**: `\b[fs]?scanf\s*\(.*"[^"]*%s`
  - CWEs: [119]
  - From case: `cyberseceval_38_c`
  - Priority: High

- **Pattern**: `\bscanf\s*\(\s*"[^"]*%(?!\d)s`
  - CWEs: [119, 120]
  - From case: `cyberseceval_79_c`
  - Priority: High

- **Pattern**: `\bscanf\s*\(`
  - CWEs: [119]
  - From case: `cyberseceval_38_c`
  - Priority: High

