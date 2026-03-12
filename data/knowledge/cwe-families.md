# CWE Family Reference for Vulnerability Detection

## Memory Safety Family (Root: CWE-119)

### CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
The root of all buffer-related vulnerabilities. Software performs operations on a memory
buffer without properly restricting read/write to the intended boundaries.

**Children:**
- **CWE-120** (Buffer Copy without Size Check): Classic buffer overflow — strcpy, strcat, sprintf
- **CWE-121** (Stack-based Buffer Overflow): Overflow on stack — local arrays, alloca
- **CWE-122** (Heap-based Buffer Overflow): Overflow on heap — malloc'd buffers
- **CWE-123** (Write-what-where): Arbitrary memory write via controlled pointer + value
- **CWE-124** (Buffer Underwrite): Writing before buffer start
- **CWE-125** (Out-of-bounds Read): Reading past buffer end (info disclosure)
- **CWE-126** (Buffer Over-read): Reading more than allocated (Heartbleed-class)
- **CWE-127** (Buffer Under-read): Reading before buffer start
- **CWE-787** (Out-of-bounds Write): Generic write past allocation bounds
- **CWE-788** (Access of Memory Location After End): Pointer arithmetic past end

**Detection signals in C/C++:**
- `strcpy`, `strcat`, `sprintf`, `gets` (no bounds checking)
- `memcpy`, `memmove` with unchecked size parameter
- Array indexing with untrusted index without bounds check
- Stack arrays with size from untrusted input
- `alloca` with untrusted size

**Detection signals in Rust:** Generally safe unless `unsafe` blocks are used.

### CWE-416: Use After Free
Memory referenced after being freed. Attacker may control freed memory contents.

**Related:** CWE-415 (Double Free)

**Detection signals:**
- `free(ptr)` followed by dereference of `ptr`
- Returning pointer to local/freed memory
- Dangling pointers in data structures after element removal

### CWE-190: Integer Overflow or Wraparound
Arithmetic result exceeds representable range. Often leads to undersized allocation → overflow.

**Children:** CWE-191 (Underflow), CWE-192 (Implicit Conversion), CWE-193 (Off-by-one),
CWE-194/195/196/197 (Various type conversion issues), CWE-680 (Integer Overflow to Buffer Overflow)

**Detection signals:**
- `malloc(count * sizeof(type))` without overflow check on multiplication
- Arithmetic on untrusted integers before use as size/index
- Implicit narrowing conversions (int64 → int32)

## Injection Family (Root: CWE-74)

### CWE-78: OS Command Injection
User input incorporated into OS commands without sanitization.

**Detection signals:**
- `system()`, `popen()`, `exec*()` with string from untrusted source
- Shell metacharacters in command arguments: `;`, `|`, `&`, `$()`, backticks
- `Runtime.getRuntime().exec()` in Java with user-controlled args
- `subprocess.call(shell=True)` in Python

### CWE-89: SQL Injection
User input incorporated into SQL queries without parameterization.

**Detection signals:**
- String concatenation in SQL: `"SELECT * FROM users WHERE id = " + input`
- `Statement.execute()` vs `PreparedStatement` in Java
- `cursor.execute(f"...")` in Python (f-string SQL)

### CWE-79: Cross-Site Scripting (XSS)
User input reflected in HTML output without encoding.

**Detection signals:**
- `innerHTML`, `document.write()` with user input in JavaScript
- `response.getWriter().write()` with unencoded user input in Java
- Template rendering without auto-escaping

### CWE-114: Process Control
Untrusted input determines which code/library is loaded.

**Detection signals:**
- `LoadLibrary()`, `dlopen()` with user-controlled path
- Dynamic class loading with untrusted class name
- Plugin systems loading from untrusted paths

## Cryptographic Weakness Family (Root: CWE-327)

### Weak Algorithms
- **CWE-327**: Use of broken/risky algorithm (DES, RC4, MD5 for hashing)
- **CWE-328**: Reversible one-way hash (MD5, SHA-1 for passwords)
- **CWE-326**: Inadequate encryption strength (short keys)

### Weak Randomness
- **CWE-330**: Insufficient randomness (predictable seeds)
- **CWE-338**: Use of PRNG in security context (rand(), Math.random())

### Configuration
- **CWE-295**: Improper certificate validation
- **CWE-310**: Cryptographic issues (general)
- **CWE-614**: Sensitive cookie without Secure flag

## Path Traversal Family (Root: CWE-22)
- **CWE-22**: Improper Limitation of a Pathname (`../` traversal)
- **CWE-23**: Relative Path Traversal
- **CWE-36**: Absolute Path Traversal

**Detection signals:**
- File operations with user-controlled path components
- Missing canonicalization before path use
- `../` sequences in path input

## Race Condition Family (Root: CWE-362)
- **CWE-362**: Concurrent Execution Using Shared Resource
- **CWE-367**: TOCTOU (Time-of-check Time-of-use)

**Detection signals:**
- Check-then-act patterns on shared resources
- File existence check followed by file operation
- Shared mutable state without synchronization

## Null Pointer Family (Root: CWE-476)
- **CWE-476**: Null Pointer Dereference
- **CWE-252**: Unchecked Return Value (leading to null deref)
- **CWE-253**: Incorrect Check of Function Return Value

**Detection signals:**
- Dereferencing return value of malloc/calloc without null check
- Using function return value without checking error conditions

## CGC-Specific Patterns
CGC challenges use custom APIs instead of standard libc:
- `cgc_allocate` → equivalent to `malloc` (memory allocation)
- `cgc_deallocate` → equivalent to `free` (memory deallocation)
- `cgc_receive` → equivalent to `recv`/`read` (input source — taint origin)
- `cgc_transmit` → equivalent to `send`/`write` (output sink)
- `cgc_read` → equivalent to `read` (input source)
- `cgc_random` → random number generation

These should be treated with the same suspicion as their libc equivalents.
Most CGC vulnerabilities are memory corruption (CWE-119 family).
