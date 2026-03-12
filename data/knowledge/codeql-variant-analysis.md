# CodeQL Variant Analysis Approach

## Core Concept
CodeQL treats code as data — it builds a relational database from source code,
then uses a query language to find patterns. The key insight for Skwaq: think
of vulnerability detection as pattern queries over a code property graph.

## Variant Analysis Workflow

### 1. Seed Finding
Start with a known vulnerability instance. For example, a confirmed
`strcpy(dest, src)` where `src` is user-controlled.

### 2. Generalize the Pattern
Abstract from the specific instance to a query:
- What makes this dangerous? (unbounded copy from tainted source)
- What are the essential elements? (source → dangerous sink, no bounds check)
- What variations exist? (different copy functions, different sources)

### 3. Taint Tracking
Follow data from untrusted sources to dangerous sinks:
- **Sources**: network input (recv, read), environment (getenv), files (fread),
  command-line args (argv)
- **Sinks**: memory operations (strcpy, memcpy), system calls (system, exec),
  SQL queries, output functions
- **Sanitizers**: bounds checks, input validation, encoding functions

### 4. Query the Graph
Express the pattern as a graph query:
```
Find all paths where:
  1. Data originates from an untrusted source
  2. Data flows through the program (possibly transformed)
  3. Data reaches a dangerous sink
  4. No sanitizer exists on the path
```

### 5. Evaluate Results
For each match:
- Is the source actually untrusted? (false positive filter)
- Is the sink actually dangerous in context? (context validation)
- Does a sanitizer exist that the analysis missed? (defense check)

## Key Patterns for Skwaq Agents

### Pattern: Source-Sink with No Sanitizer
Most critical — direct flow from untrusted input to dangerous operation.
Example: `recv()` → buffer → `strcpy()` without length check.

### Pattern: Integer Overflow in Size Calculation
Multiplication/addition on untrusted values used as allocation size.
Example: `count * sizeof(item)` overflows, `malloc(small_value)` allocates
too little, subsequent write overflows.

### Pattern: Missing Null Check
Function returns pointer that may be NULL, caller dereferences without check.
Example: `malloc()` returns NULL on OOM, code proceeds to write through it.

### Pattern: TOCTOU (Time-of-Check Time-of-Use)
Security check separated from the operation it guards.
Example: `access(path)` check, then `open(path)` — attacker changes path between.

### Pattern: Type Confusion
Data interpreted as wrong type, especially in C unions or void* casts.
Example: Treating int as pointer, or casting between incompatible struct types.

## Applying to Skwaq's Agent Pipeline

1. **attack-surface agent**: Identifies sources (entry points) and sinks (dangerous operations)
2. **vuln-hunter agent**: Traces flows from sources to sinks, looking for missing sanitizers
3. **exploit-analyst agent**: Evaluates if the flow is actually exploitable
4. **defense-analyst agent**: Checks for sanitizers the earlier agents may have missed
5. **verdict-synthesizer**: Weighs evidence from all agents to reach final verdict

The key question each agent should ask:
"Is there a path from untrusted input to this dangerous operation,
and if so, what prevents exploitation?"
