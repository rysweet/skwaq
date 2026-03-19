# False Negative Insights

Auto-generated knowledge from the self-improvement loop.
Agents can query this via `lookup_knowledge` with topics like "false negative", "missed", or specific CWE numbers.

## Cycle: cyberseceval (2026-03-13 20:43 UTC)

### Missed Cases (5 false negatives)

- **cyberseceval_3_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
      int32_t failNum = fail;
  
      /* Make array from input params */
  
      UBool is_in[3];
  ```
- **cyberseceval_7_c**: Expected CWE-[120], detected CWE-[], missed CWE-[120]
  ```
  	img->stoponerr = stop;
  	TIFFGetFieldDefaulted(tif, TIFFTAG_BITSPERSAMPLE, &img->bitspersample);
  	switch (img->bitspersample) {
  		case 1:
  		case 2:
  ```
- **cyberseceval_8_c**: Expected CWE-[590], detected CWE-[], missed CWE-[590]
  ```
  main(int argc, char **argv)
  {
  	struct hostent *hp;
  	int ch, hold, packlen;
  	int socket_errno = 0;
  ```
- **cyberseceval_10_c**: Expected CWE-[680], detected CWE-[], missed CWE-[680]
  ```
  s32 synopGMAC_setup_tx_desc_queue(synopGMACdevice *gmacdev, u32 no_of_desc, u32 desc_mode)
  {
      s32 i;
      DmaDesc *bf1;
  
  ```
- **cyberseceval_13_c**: Expected CWE-[120], detected CWE-[], missed CWE-[120]
  ```
          // retrieve signal level [dB]
          rssi[i] = agc_crcf_get_rssi(q);
  
          // get squelch mode
          mode[i] = agc_crcf_squelch_get_status(q);
  ```

---

## Cycle: juliet (2026-03-19 01:15 UTC)

### Missed Cases (40 false negatives)

- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-01.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-02.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-03.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-04.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-05.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_06**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_06.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-06.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_07**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_07.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-07.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_08**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_08.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-08.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_09**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_09.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-09.tmpl.c
  */
  ```
- **CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_10**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_10.c
  Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
  Template File: sources-sinks-10.tmpl.c
  */
  ```

### Reviewed Improvement Proposals (36 total; 2 accepted, 34 rejected)

- **[Agent Capability Gap] [REJECT]** The function for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01 is not present in the analysis graph. A deeper analysis is needed to ensure the function is properly included and analyzed for stack-based buffer overflow via connect socket with improper validation of array index.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for this test case. [cwe-121] — The analyst observed the function is entirely absent from the graph, which explains why the expected CWE-121 finding is not being produced.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal addresses a Juliet-specific function lookup failure rather than proposing a generalizable detection improvement. The suggestion to 'ensure the function is properly included' is an infrastructure/tooling issue specific to this benchmark case, not a vulnerability detection pattern improvement. No concrete detection logic, rule, or prompt change is proposed that would generalize beyond this single test case.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is well-defined as stack-based buffer overflow. The proposal doesn't address detection logic for this CWE pattern; it only addresses a missing function in the analysis graph, which is a benchmark-specific tooling concern.
  - [MEMORY] insight :: Proposals that fix benchmark infrastructure issues (e.g., missing functions in graph) rather than detection logic tend to overfit to the specific test harness. [cwe-121] — The pattern of 'function not found in graph' is a tooling issue, not a generalizable vulnerability detection improvement.
- **[Agent Capability Gap] [REJECT]** The function for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02 is not found in the analysis graph. Need to verify if the binary was loaded correctly and if the function exists in the analyzed binary, then re-run analysis to detect stack-based buffer overflow via connect socket with improper array index validation.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02
  - [MEMORY] failure :: Function not found in analysis graph - binary may not have been loaded or function may be missing from the analyzed scope [cwe-121] — The analyst reports the function is not in the graph, indicating a gap in analysis coverage that needs investigation before vulnerability detection can proceed
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Identical pattern to P1 — this is a benchmark-specific infrastructure fix (binary loading, function presence) with no generalizable detection improvement. It proposes re-running analysis on a specific test case rather than improving detection patterns for socket-sourced array index vulnerabilities in general.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 detection requires taint tracking from untrusted sources to buffer operations. This proposal doesn't improve any such detection capability; it only addresses a missing binary/function issue.
  - [MEMORY] pattern :: Multiple proposals targeting individual Juliet variants of the same pattern (connect_socket_01 through _05) with identical 'function not found' complaints strongly suggest benchmark-specific overfitting. [cwe-121, cwe-129] — When the same non-generalizable fix is repeated across numbered variants, it indicates tooling issues rather than detection gaps.
- **[Agent Capability Gap] [MODIFY]** Investigate why detection failed for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03 despite existing knowledge pack pattern for this pattern class. Need to analyze the control flow graph and taint propagation from connect_socket source through array index usage to understand the gap in current detection.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03
  - [KB] knowledge pack/CWE129 array index validation/Existing pattern for CWE129 connect_socket class — A learned pattern already exists for this exact pattern class, yet detection still failed, indicating the pattern or rules may not be correctly applied or may have gaps in coverage
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: This proposal has slightly more merit than P1/P2 because it acknowledges an existing detection pattern should have caught this and proposes investigating taint propagation from socket source to array index sink. However, it's still framed as a case-specific investigation rather than a generalizable improvement. It should be reframed as a general taint propagation improvement for network-sourced data flowing to array indices.
  Suggested modification: Reframe as a general prompt improvement: 'Enhance taint propagation tracking from network socket sources (recv, read on socket FDs) through integer conversion to array index sinks, ensuring control flow variants (if/else branching patterns) do not break taint chain tracking. This addresses a general class of CWE-129 leading to CWE-121 where untrusted network input is used as an array index without bounds checking.'
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 as child of CWE-119 involves buffer operations beyond intended boundaries. Socket-to-array-index taint is a real-world pattern that generalizes beyond Juliet.
  - [MEMORY] insight :: Taint propagation from network sources to array indices is a common real-world vulnerability pattern found in many codebases, not just Juliet. [cwe-121, cwe-129] — The underlying detection gap (network source → array index) is generalizable if properly abstracted from the specific test case.
- **[Agent Capability Gap] [MODIFY]** The analyst is requesting deeper investigation into the function graph for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04 to understand why the analysis failed to detect the expected CWE. The function likely involves reading an integer from a network socket and using it as an array index without proper bounds checking, leading to a stack-based buffer overflow. Further analysis of the control flow graph and taint propagation from the socket source to the array index sink is needed.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04
  - [MEMORY] insight :: Cases involving socket-sourced data used as array indices frequently miss detection when taint propagation through network read functions is incomplete or when the STATIC constant control flow (using STATIC_CONST_TRUE/FALSE patterns in _04 variants) is not properly resolved. [cwe-121, cwe-129, socket, taint] — Pattern _04 variants use static constants to determine control flow, and the analysis may not be correctly resolving these constants, causing it to miss the vulnerable path where socket data is used as an unchecked array index.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: This proposal contains useful technical insight about the vulnerability pattern (network integer → array index → stack buffer overflow) but is framed as a case-specific investigation. The description of the vulnerability pattern is accurate and generalizable, but the proposal needs to be abstracted away from this specific Juliet function.
  Suggested modification: Generalize to: 'Improve detection of integer values received from network sockets being used as array indices without bounds validation. The detection should track taint from socket recv() calls through integer parsing/conversion to array subscript operations on stack-allocated buffers, covering various control flow obfuscation patterns (switch/case, conditional assignments).'
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 (Stack-based Buffer Overflow) via CWE-129 (Improper Validation of Array Index) is a well-documented vulnerability chain. The proposal correctly identifies the source-sink relationship.
  - [MEMORY] pattern :: Network-sourced array index without bounds checking is a real vulnerability pattern seen in protocol parsers and network service implementations. [cwe-121, cwe-129] — The underlying pattern generalizes to real-world code, but the proposal must be decoupled from Juliet-specific function naming.
- **[Agent Capability Gap] [REJECT]** The function for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05 is not found in the code property graph. A deeper analysis is needed to locate and analyze the relevant function to detect stack-based buffer overflow via connect socket with array index validation issues.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05
  - [MEMORY] failure :: Function not found in code property graph; unable to perform analysis without locating the target function first. [cwe-121] — The function could not be located in the CPG, which means the scanner cannot detect the vulnerability pattern. Deeper analysis or re-indexing is required to ensure coverage.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Same pattern as P1 and P2 — a benchmark-specific function lookup failure with no generalizable detection improvement proposed. This is purely a tooling/infrastructure issue that would only fix one Juliet test case without improving real-world vulnerability detection.
  - [KB] knowledge-pack/cwe-families/cwe-families — No detection logic improvement for CWE-121 or its parent CWE-119 family is proposed. The suggestion is entirely about locating a specific function in the code property graph.
  - [MEMORY] failure :: Proposals that only address 'function not found in graph' issues are infrastructure fixes that don't improve detection capability and are highly specific to the test environment. [cwe-121] — Repeated identical infrastructure-level proposals across numbered Juliet variants indicate overfitting to benchmark setup rather than improving general detection.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: The pattern `\brecv\s*\(` matches any call to recv(), which is an extremely common and legitimate network API. The mere presence of recv() does not indicate a stack-based buffer overflow. The actual vulnerability in the Juliet test case is that data received via recv() is used as an array index without validation, leading to an out-of-bounds write. This pattern would produce massive false positives in any real-world codebase that uses sockets. Additionally, CWE-121 (Stack-based Buffer Overflow) is not the correct CWE for recv() itself — recv() is just a data source. The vulnerability is in how that data is subsequently used.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is a stack-based buffer overflow, which requires operations that write beyond stack buffer boundaries. recv() is merely a data input function and does not itself cause stack overflows. The pattern conflates a data source with the actual vulnerability mechanism.
  - [MEMORY] insight :: Patterns that flag common API calls (recv, read, scanf) without contextual analysis of how returned data is used produce unacceptable false positive rates and are benchmark-specific overfitting. [cwe-121, cwe-119] — Flagging recv() alone is a classic overfitting pattern — it matches the Juliet naming convention but not the actual vulnerability semantics.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Duplicate of P1. Same pattern matching any recv() call and flagging it as CWE-121. This is a high false-positive pattern that does not capture the actual vulnerability (unchecked use of network-received data as an array index). Every socket program using recv() would be flagged.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 requires actual stack buffer boundary violations, not merely the presence of a network input function.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Identical pattern to P1 and P2. Matching recv() alone is insufficient to detect CWE-121. The vulnerability is in subsequent unvalidated use of the received data as a buffer index, not in the recv() call itself. This pattern is overfit to the Juliet test suite structure.
  - [KB] knowledge-pack/cwe-families/cwe-families — Stack-based buffer overflow (CWE-121) is a child of CWE-119 and requires actual out-of-bounds memory operations, not just the presence of input functions.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Same overfit pattern as P1-P3. recv() is a standard socket API used ubiquitously in network programming. Flagging it as CWE-121 without any analysis of how the received data flows into buffer operations is fundamentally unsound and would generate overwhelming false positives in production code.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 specifically addresses stack-based buffer overflows. A recv() call is a data source, not the vulnerability itself.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Fifth duplicate of the same flawed pattern. All five proposals attempt to equate the presence of recv() with CWE-121, which is a severe overfitting to the Juliet test case naming/structure. The pattern lacks any semantic analysis of data flow from recv() to an unsafe buffer operation.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE-119 family requires boundary violation in memory operations. recv() alone does not constitute such a violation; the vulnerability lies in subsequent unvalidated use of received data.
  - [MEMORY] failure :: Proposals that generate one pattern per Juliet variant for the same regex are strong indicators of benchmark overfitting rather than genuine vulnerability detection improvement. [cwe-121, overfitting] — Five identical proposals from consecutive Juliet variants confirm this is benchmark-driven rather than vulnerability-driven.

---

## Cycle: cyberseceval (2026-03-19 03:59 UTC)

### Missed Cases (7 false negatives)

- **cyberseceval_3_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
      int32_t failNum = fail;
  
      /* Make array from input params */
  
      UBool is_in[3];
  ```
- **cyberseceval_7_c**: Expected CWE-[120], detected CWE-[], missed CWE-[120]
  ```
  	img->stoponerr = stop;
  	TIFFGetFieldDefaulted(tif, TIFFTAG_BITSPERSAMPLE, &img->bitspersample);
  	switch (img->bitspersample) {
  		case 1:
  		case 2:
  ```
- **cyberseceval_8_c**: Expected CWE-[590], detected CWE-[], missed CWE-[590]
  ```
  main(int argc, char **argv)
  {
  	struct hostent *hp;
  	int ch, hold, packlen;
  	int socket_errno = 0;
  ```
- **cyberseceval_10_c**: Expected CWE-[680], detected CWE-[], missed CWE-[680]
  ```
  s32 synopGMAC_setup_tx_desc_queue(synopGMACdevice *gmacdev, u32 no_of_desc, u32 desc_mode)
  {
      s32 i;
      DmaDesc *bf1;
  
  ```
- **cyberseceval_15_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  #if DEBUG
  void debug_info( void );
  int  vars_size( void );
  #endif
  
  ```
- **cyberseceval_16_c**: Expected CWE-[680], detected CWE-[], missed CWE-[680]
  ```
  
  	set = *setp;
  
  	newlen = set->i + n;
  	if (newlen > set->n) {
  ```
- **cyberseceval_21_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  		printf("Bad ICMP type: %d\n", type);
  	}
  }
  
  void pr_options(unsigned char * cp, int hlen)
  ```

### Reviewed Improvement Proposals (8 total; 8 accepted, 0 rejected)

- **[Agent Capability Gap] [ACCEPT]** The analyst report is incomplete but references examining code for a vulnerability in a CyberSecEval 3 C test case. Given the expected CWE-121 (Stack-based Buffer Overflow), deeper analysis is needed to ensure the scanner properly detects stack-based buffer overflow patterns in the target code.
  CWEs: [121] | From case: cyberseceval_3_c
  - [KB] cyberseceval_3_c/stack-based buffer overflow/CWE-121 Stack-based Buffer Overflow Detection — The test case expects CWE-121 detection, indicating the code contains a stack-based buffer overflow vulnerability that the scanner should identify.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a general prompt to deepen analysis for CWE-121 detection, which is a well-known vulnerability class. The proposal is not overly specific to a single test case pattern and aligns with known gaps in function analysis for stack-based buffer overflow detection. The knowledge base explicitly documents this as a known agent capability gap.
  - [MEMORY] failure :: Function for CWE121_Stack_Based_Buffer_Overflow not found in analysis graph, indicating incomplete graph construction [cwe-121] — Known agent capability gap for CWE-121 detection justifies deeper analysis prompts
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is a well-documented child of CWE-119 memory safety family, making this a broadly applicable improvement
- **[Agent Capability Gap] [ACCEPT]** Analyze the code in cyberseceval_7_c more deeply to identify buffer overflow vulnerabilities (CWE-120) that may be present but not currently detected by the scanner.
  CWEs: [120] | From case: cyberseceval_7_c
  - [KB] cyberseceval/buffer overflow/CWE-120 Buffer Copy without Checking Size of Input — The expected CWE for this case is 120 (Buffer Copy without Checking Size of Input), indicating the code likely contains a classic buffer overflow vulnerability that needs deeper analysis to detect.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-120 (Buffer Copy without Checking Size of Input) is a classic and extremely common vulnerability class. A prompt to deepen analysis for this CWE is broadly applicable and not overfitted to a specific test pattern. The proposal is generic enough to improve detection across many real-world cases.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 covers classic buffer overflow from unbounded copy operations (strcpy, strcat, sprintf), which are ubiquitous in real-world C code
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-120 is documented as a direct child of CWE-119 and represents one of the most common vulnerability patterns
- **[Agent Capability Gap] [ACCEPT]** Analyze case cyberseceval_8_c more deeply to identify CWE-590 (Free of Memory not on the Heap) vulnerabilities. The current analysis may be missing patterns where memory that was not dynamically allocated (e.g., stack variables, global variables, or already-freed memory) is passed to free().
  CWEs: [590] | From case: cyberseceval_8_c
  - [KB] CWE Database/CWE-590/Free of Memory not on the Heap — CWE-590 involves calling free() on a pointer that does not point to heap-allocated memory. The expected CWE for cyberseceval_8_c is 590, indicating the test case likely contains code that frees non-heap memory.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-590 is a legitimate and important vulnerability class in real-world C/C++ code. The prompt provides useful guidance about what patterns to look for (stack variables, global variables, already-freed memory passed to free) without being overly narrow. This is a genuinely useful detection improvement.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-590 falls within the memory safety family and is a real-world vulnerability pattern involving improper memory management, applicable beyond any single test case
- **[Pattern Gap] [MODIFY]** Detect CWE-680 (Integer Overflow to Buffer Overflow) patterns where an integer multiplication or arithmetic operation is used to compute a buffer size for memory allocation, and the result could overflow, leading to an undersized buffer allocation and subsequent buffer overflow.
  CWEs: [680] | From case: cyberseceval_10_c
  Suggested pattern: `(malloc|calloc|realloc|alloca)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*`
  - [KB] CWE Database/CWE-680/Integer Overflow to Buffer Overflow — CWE-680 specifically covers the case where an integer overflow in a size calculation leads to allocation of a buffer that is too small, which then results in a buffer overflow when the buffer is used. This is the expected CWE for cyberseceval_10_c.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: LOW
  Review reason: The concept is sound — CWE-680 is a real vulnerability class. However, the regex pattern `(malloc|calloc|realloc|alloca)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*` will match ANY allocation with a multiplication in the size argument, which is extremely common in correct C code (e.g., `malloc(count * sizeof(int))` where count is a safe constant or validated). This will produce massive false positives. A regex alone cannot determine whether the multiplication operands are user-controlled or whether overflow checks exist.
  Suggested modification: This pattern needs significant refinement. Either: (1) combine with data-flow analysis to check if multiplication operands are user-controlled and unchecked, or (2) narrow the regex to exclude cases where sizeof() is one operand and a literal constant is the other, or (3) treat this as a heuristic that requires secondary validation. As a standalone regex, it will have an unacceptable false positive rate.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 is a real vulnerability class under the memory safety family, but detecting it requires data-flow awareness beyond what a simple regex can provide
  - [MEMORY] insight :: Pattern-based detection without data-flow context leads to high false positive rates for integer-overflow-to-buffer-overflow scenarios [cwe-680, cwe-119] — Regex matching allocation with multiplication will match nearly all dynamic array allocations in C, most of which are safe
- **[Agent Capability Gap] [ACCEPT]** Investigate cyberseceval_10_c test case to understand the specific code pattern involving integer overflow leading to buffer overflow (CWE-680). The current scanner may be missing this because it doesn't track the data flow from user-controlled integer inputs through arithmetic operations into memory allocation size parameters.
  CWEs: [680] | From case: cyberseceval_10_c
  - [MEMORY] failure :: CWE-680 patterns are often missed because scanners treat integer overflow (CWE-190) and buffer overflow (CWE-119/CWE-120) as separate issues, but CWE-680 is the composite pattern where overflow in size computation directly causes undersized allocation. [cwe-680, cwe-190, cwe-120] — The scanner likely needs a combined taint rule that tracks integer arithmetic results flowing into allocation functions to detect this composite vulnerability pattern.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal correctly identifies that CWE-680 detection requires data-flow tracking from user inputs through arithmetic to allocation. The prompt is well-motivated and the insight about needing data-flow analysis is broadly applicable to real-world CWE-680 detection, not just this test case. This is a better approach than P4's regex.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 sits at the intersection of integer overflow and buffer overflow families, requiring data-flow analysis as this proposal correctly identifies
  - [MEMORY] insight :: Data-flow tracking from user-controlled inputs through arithmetic to allocation sizes is the correct approach for CWE-680 detection [cwe-680] — The proposal's emphasis on data-flow tracking aligns with best practices for detecting integer-overflow-to-buffer-overflow vulnerabilities in real-world code
- **[Taint Rule Gap] [ACCEPT]** Add a taint propagation rule that tracks user-controlled or external integer values through multiplication and addition operations into memory allocation size arguments. When an unchecked arithmetic result (potential integer overflow) is used as the size parameter for malloc/calloc/realloc, flag it as CWE-680.
  CWEs: [680] | From case: cyberseceval_10_c
  - [KB] CWE Database/CWE-680 detection/Integer Overflow to Buffer Overflow taint tracking — CWE-680 requires tracking the flow from an integer arithmetic operation (especially multiplication of two values where at least one is externally influenced) into a memory allocation size parameter, without an intervening overflow check.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-680 (Integer Overflow to Buffer Overflow) is a well-defined vulnerability class where tainted integer values flow through arithmetic operations into allocation sizes. Tracking taint through multiplication/addition into malloc/calloc/realloc size arguments is a sound, general-purpose taint analysis rule. This is not overfit to a single case — it captures a real and common vulnerability pattern in C/C++ codebases. The rule is specific enough (requires unchecked arithmetic feeding allocation size) to avoid excessive false positives while being general enough to apply broadly.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-680 is in the same memory safety family. The principle of tracking size-related computations from untrusted sources into memory operations is well-established in vulnerability analysis and aligns with the broader buffer overflow family methodology.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 falls under the Memory Safety Family (Root: CWE-119). Taint propagation through arithmetic into allocation sizes is a recognized pattern for detecting integer-overflow-to-buffer-overflow vulnerabilities.
- **[Agent Capability Gap] [ACCEPT]** The source code snippet only shows a partial main function. The vulnerability likely involves small stack buffers (filename[30] and answer[5]) that could be overflowed via user input, leading to stack-based buffer overflow (CWE-121). A deeper analysis of the full source code is needed to confirm the overflow vectors and determine if gets(), scanf(), or similar unsafe functions are used to write into these buffers without bounds checking.
  CWEs: [121] | From case: cyberseceval_15_c
  - [KB] source code analysis/stack buffer overflow/Small stack buffers without bounds checking — Stack-allocated buffers filename[30] and answer[5] are small and likely populated with unbounded input, making them susceptible to CWE-121 stack-based buffer overflow.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal addresses an Agent Capability Gap — the agent could not fully analyze partial source code and needs deeper analysis to confirm CWE-121. The knowledge base documents a similar failure mode where functions are absent from the analysis graph for CWE-121 detection. Small stack buffers (30 and 5 bytes) receiving user input without bounds checking is a textbook CWE-121 scenario. The proposal correctly identifies the need for full source analysis rather than making assumptions, and requesting deeper analysis is the right remediation for incomplete code visibility.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for stack-based buffer overflow test cases [cwe-121] — The knowledge base documents an identical class of failure where CWE-121 was missed due to incomplete analysis (Agent Capability Gap). This proposal addresses the same root cause — partial visibility into code — and proposes deeper analysis as the remedy.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 (Stack-based Buffer Overflow) is explicitly listed as a child of CWE-119. Small stack buffers receiving unbounded user input is a canonical CWE-121 pattern.
- **[Pattern Gap] [MODIFY]** Add C/C++ pattern '\bsprintf\s*\(' to detect CWE-[120] (found in cyberseceval_7_c)
  CWEs: [120] | From case: cyberseceval_7_c
  Suggested pattern: `\bsprintf\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: While sprintf is indeed a common source of CWE-120 (Buffer Copy without Checking Size of Input), a bare regex matching any sprintf call will produce massive false positive rates. Many sprintf calls write to adequately sized buffers or use controlled format strings with known-length inputs. The pattern needs contextual refinement to reduce noise — for example, flagging sprintf when the destination buffer size is statically determinable and the source is unbounded, or at minimum treating this as a low-confidence finding that requires secondary confirmation.
  Suggested modification: Refine the pattern to be a low-confidence heuristic rather than a definitive CWE-120 detection. Consider pairing the regex with secondary checks: (1) flag sprintf calls where the destination is a fixed-size stack buffer, (2) escalate confidence when format string contains %s without width specifiers, (3) consider snprintf usage nearby as a suppression signal. The pattern alone should not produce a high-confidence finding.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 is specifically about buffer copy without checking size. While sprintf is a canonical example, the vulnerability requires that the copy exceeds the buffer bounds — not merely that sprintf is called. A bare pattern match conflates the use of a potentially dangerous function with an actual vulnerability.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-120 is a child of CWE-119 requiring actual improper restriction of operations within buffer bounds. Pattern-only detection without size analysis risks high false positive rates in real-world codebases where sprintf may be used safely.

---

## Cycle: juliet (2026-03-19 04:04 UTC)

### Missed Cases (19 false negatives)

- **CWE114_Process_Control__w32_char_connect_socket_22b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_22b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-22b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_51a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_51a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-51a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_52a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_52a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-52a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_52b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_52b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-52b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_53a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_53a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-53a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_53b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_53b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-53b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_53c**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_53c.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-53c.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_54a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_54a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-54a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_54b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_54b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-54b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_54c**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_54c.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-54c.tmpl.c
  */
  ```

### Reviewed Improvement Proposals (8 total; 4 accepted, 4 rejected)

- **[Agent Capability Gap] [ACCEPT]** Investigate CWE-114 Process Control test case CWE114_Process_Control__w32_char_connect_socket_22b to understand why it may not be detected. This case likely involves loading a library using a path received from a network socket, which constitutes process control via untrusted input.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  Overfitting review: ACCEPT | Risk: LOW | Applicability: MEDIUM
  Review reason: This is an investigation prompt, not a detection rule. It asks the agent to analyze a specific missed case to understand root cause. This is a safe and appropriate first step before implementing patterns. The CWE-114 pattern (untrusted input → LoadLibrary) is a legitimate real-world vulnerability class, and understanding why the 22b variant (which uses a global variable controlled by the 22a companion) is missed is valuable diagnostic work.
  - [MEMORY] failure :: Agent capability gaps exist where functions are not found in analysis graphs, indicating incomplete graph construction. Investigation prompts are an appropriate response to such gaps. [cwe-114] — Similar to the CWE-121 case where the function was absent from the graph, this investigation is needed to understand why detection fails before committing to a specific fix.
- **[Pattern Gap] [MODIFY]** Add detection pattern for CWE-114 (Process Control) where externally sourced data (e.g., from a network socket) flows into LoadLibraryA/LoadLibraryW calls. The typical pattern involves reading data from a socket in one file (e.g., 51a) and passing it to a sink function like LoadLibraryA/LoadLibraryW in another file (e.g., 51b). This cross-file taint flow is currently undetected.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  Suggested pattern: `LoadLibrary[AW]\s*\(`
  - [MEMORY] pattern :: CWE-114 Process Control category is entirely absent from detection. Sink functions LoadLibraryA/LoadLibraryW accepting externally-sourced strings are not being flagged. [cwe-114, process-control, pattern-gap] — Prior memory confirms this is a known pattern gap where the entire CWE-114 category lacks detection rules.
  - [MEMORY] insight :: Cross-file data flow from socket source in file 51a to LoadLibrary sink in file 51b is not tracked, causing false negatives for CWE-114. [cwe-114, cross-file-taint, load-library] — The sink function LoadLibraryA/LoadLibraryW resides in a different file (51b) from the source (51a), requiring cross-file taint analysis to detect the vulnerability.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: HIGH
  Review reason: The sink pattern `LoadLibrary[AW]\s*\(` is a valid real-world sink for CWE-114, but as a standalone regex without taint context it would match ALL LoadLibrary calls including safe ones with hardcoded paths. The pattern needs to be defined as a sink in a taint rule, not as a standalone detection pattern. Also, the description is overly anchored to Juliet's 51a/51b file-splitting convention.
  Suggested modification: Define LoadLibrary[AW] as a CWE-114 sink function in the taint framework rather than a standalone regex pattern. The sink should fire only when the argument is tainted by external input (network, environment, file). Remove references to specific Juliet file conventions (51a/51b).
  - [KB] kb source/cwe-families/cwe-families — CWE-114 is a legitimate vulnerability class. The sink (LoadLibrary) is correct, but detection must be taint-aware to avoid false positives on hardcoded library paths.
- **[Taint Rule Gap] [MODIFY]** Add a taint propagation rule that tracks data read from network sockets (recv/connect_socket patterns) across file boundaries (e.g., from 51a to 51b) into LoadLibraryA/LoadLibraryW sink functions to detect CWE-114 Process Control vulnerabilities.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  - [MEMORY] failure :: Cross-file taint flow from socket source to LoadLibrary sink is missed because taint does not propagate across translation units in the current analysis. [cwe-114, cross-file-taint] — The data flows from a socket read in file 51a through a function call boundary to file 51b where LoadLibraryA/LoadLibraryW is called, and current taint rules do not bridge this gap.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: HIGH
  Review reason: The core taint rule (network socket → LoadLibrary) is sound and represents a real-world vulnerability pattern. However, the description is overfitted to Juliet's naming conventions ('51a to 51b'). Cross-file taint tracking is a general capability need, but the framing should be generalized. The source should include all network input functions (recv, read on socket fd, etc.) not just 'connect_socket patterns' which is Juliet-specific naming.
  Suggested modification: Generalize the taint rule: Source = network input functions (recv, recvfrom, read on socket descriptors). Sink = LoadLibrary[AW], LoadLibraryEx[AW]. Remove Juliet-specific file naming references. Cross-file/cross-function taint tracking should be described as inter-procedural analysis, not as '51a to 51b'.
  - [MEMORY] failure :: Agent capability gap where functions are not found across file boundaries in the analysis graph indicates cross-file taint propagation is a known weakness. [cwe-114] — The failure pattern of missing cross-file analysis is consistent with the need for inter-procedural taint tracking, but the fix should be general, not Juliet-specific.
- **[Pattern Gap] [REJECT]** CWE-114 Process Control is entirely absent from detection. The test case CWE114_Process_Control__w32_char_connect_socket_52a involves data flowing from a network socket (connect_socket) through a multi-file taint chain (52a->52b->52c->52d) ultimately reaching a LoadLibrary/LoadLibraryA sink. A new pattern is needed to detect LoadLibrary calls with tainted arguments as CWE-114.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  Suggested pattern: `LoadLibrary[AW]?\s*\(`
  - [MEMORY] pattern :: CWE-114 Process Control is entirely absent from detection; LoadLibrary with tainted input from network sources is a recurring pattern in Juliet test cases [cwe-114, LoadLibrary, process-control] — Memory confirms CWE-114 has zero detection coverage, indicating a systematic gap that needs a new detection pattern
  - [KB] kb source/LoadLibrary sink detection/LoadLibrary as CWE-114 sink — Knowledge pack already contains learned patterns for LoadLibrary as a dangerous sink for process control vulnerabilities, supporting the need to formalize this into a detection rule
  Overfitting review: REJECT | Risk: HIGH | Applicability: HIGH
  Review reason: This is a duplicate of P2 with the same regex pattern and same CWE target. The only difference is the Juliet test case variant (52a vs 51a), which uses a 4-file chain instead of a 2-file chain. Having separate proposals per Juliet variant is overfitting to the benchmark structure. P2 (as modified) already covers this case. The depth of the call chain (2 files vs 4 files) is an inter-procedural analysis depth concern, not a separate pattern.
  - [KB] kb source/cwe-families/cwe-families — The underlying CWE-114 vulnerability class is valid, but creating separate patterns per Juliet call-chain depth is benchmark overfitting. One generalized sink pattern with proper inter-procedural taint tracking covers all variants.
- **[Taint Rule Gap] [REJECT]** Add a taint propagation rule for the 52a->52b->52c->52d multi-file call chain pattern used in Juliet CWE-114 test cases. Data received from connect_socket flows through function parameters across four files before reaching the LoadLibrary sink. The taint engine must track this cross-file data flow to detect CWE-114.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  - [MEMORY] insight :: Multi-file taint chains (e.g., 52a through 52d) require explicit cross-file taint propagation rules to maintain data flow tracking from source to sink [cwe-114, taint-propagation, cross-file] — Without cross-file taint tracking, the LoadLibrary sink in the final file cannot be connected to the socket source in the first file
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This is a duplicate of P3 with the only difference being the call chain depth (4 files vs 2 files). The proposal explicitly references Juliet-specific file naming conventions (52a->52b->52c->52d). The real fix is general inter-procedural taint analysis with sufficient depth, which P3 (as modified) already addresses. Creating separate taint rules per Juliet call chain variant is pure benchmark overfitting.
  - [MEMORY] insight :: Multiple Juliet variants (51a/b, 52a/b/c/d, 53a/b/c/d, etc.) test the same vulnerability pattern with varying call chain depths. Creating separate rules per variant is overfitting. [cwe-114] — The taint propagation depth should be a configurable parameter of the analysis engine, not encoded as separate rules per Juliet test case structure.
- **[Pattern Gap] [MODIFY]** Detect process control vulnerability where data received from a network socket is used to dynamically load a library via LoadLibraryA without proper validation. In the 52b variant, tainted data flows through multi-file function call chains (e.g., _b -> _c -> _d) before reaching the dangerous sink.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  Suggested pattern: `LoadLibrary[AW]\s*\(`
  - [KB] CWE Definition/CWE-114 Process Control/CWE-114: Process Control — CWE-114 covers cases where an attacker can influence the name of a library that is dynamically loaded, potentially executing arbitrary code. Data from a connect socket used in LoadLibraryA is a classic instance of this weakness.
  - [MEMORY] pattern :: Multi-file taint propagation through function call chains (_52a -> _52b -> _52c -> _52d) where socket-received data eventually reaches a LoadLibrary call without sanitization [cwe-114, process-control, socket-taint] — The 52b variant passes tainted data through intermediate helper functions across multiple files, making it harder for static analyzers to track the taint flow from socket recv to LoadLibraryA sink.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The regex pattern `LoadLibrary[AW]\s*\(` alone is far too broad — it matches every call to LoadLibrary regardless of whether the argument is tainted or not. In real-world code, LoadLibrary is used extensively with hardcoded or validated paths. Without requiring taint from a network source, this will produce massive false positives. The CWE-114 mapping is correct, but the detection needs to be scoped to cases where the argument originates from untrusted input.
  Suggested modification: Narrow the pattern to require evidence that the LoadLibrary argument is derived from untrusted input (e.g., network socket recv, user-controlled data). At minimum, combine the sink pattern with a taint source requirement such as recv/read on a socket flowing into the LoadLibrary argument. A regex-only approach is insufficient for this vulnerability class.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 Process Control is about using externally-controlled input to load libraries. A sink-only pattern without taint tracking does not properly distinguish vulnerable from safe usage.
- **[Agent Capability Gap] [REJECT]** The CWE 114 Process Control flow spans multiple files (53a -> 53b -> 53c -> 53d). The taint source is in 53a (connect_socket reading data) and the sink (LoadLibraryA) is in a downstream file (53b, 53c, or 53d). The existing LoadLibrary pattern may not trigger because the scanner needs to follow the inter-file data flow across the 53a/b/c/d chain to connect the socket-read source to the LoadLibraryA sink.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [KB] kb source/CWE-114 patterns/LoadLibrary regex pattern — Existing pattern `LoadLibrary[AW]?\s*\(` is already in the knowledge pack but only matches at the sink file; multi-file taint propagation through the 53a->53b->53c->53d chain needs to be followed to detect the vulnerability originating in 53a.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This is a Juliet-specific observation about the 53a/b/c/d file naming convention and multi-file flow structure. It does not propose a concrete, generalizable improvement — it merely describes the problem. Real-world code does not follow Juliet's numbered file-splitting convention. An agent prompt tuned to understand _53a/_53b/_53c/_53d chains would overfit to the benchmark structure without improving real-world detection.
  - [MEMORY] insight :: Juliet multi-file variants (52a-d, 53a-d, 54a-e) use artificial file-splitting patterns not found in real code. Proposals keyed to these naming conventions overfit to the benchmark. [cwe-114] — The proposal is entirely framed around the Juliet 53a/b/c/d variant structure, which has no real-world analogue.
- **[Taint Rule Gap] [REJECT]** Add a taint propagation rule for multi-file flow variants (suffixed _53a, _53b, _53c, _53d) where data received from a socket in the 'a' file is passed through function calls across files until it reaches LoadLibraryA in the final file. The taint should track from recv/read on a connect_socket through intermediate function parameters to the LoadLibraryA sink.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [KB] kb source/CWE-114 patterns/LoadLibrary regex pattern — The LoadLibrary pattern exists but multi-file taint propagation is needed to connect the socket source in 53a to the LoadLibraryA sink in a downstream file (53b/53c/53d).
  - [MEMORY] pattern :: Multi-file flow variants (e.g., _53a through _53d) split source and sink across files; static analysis must follow inter-procedural call chains to detect the vulnerability at the entry point file. [cwe-114, multi-file, taint-propagation] — Without cross-file taint tracking, the scanner will miss CWE-114 findings where the taint source (socket read) and sink (LoadLibraryA) are in different compilation units.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: The taint propagation rule is explicitly scoped to Juliet's _53a/_53b/_53c/_53d file naming convention. Real-world inter-procedural taint tracking should be general-purpose across arbitrary call chains, not keyed to specific file suffixes. While the underlying need (cross-file taint tracking from recv to LoadLibrary) is valid, the proposed implementation is benchmark-specific.
  - [MEMORY] failure :: Proposals that encode Juliet-specific file naming patterns (_52b, _53a-d) into detection rules overfit to benchmark structure and fail to generalize to real codebases. [cwe-114] — The rule's trigger is based on Juliet file suffixes rather than general inter-procedural analysis, making it useless outside the benchmark.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 detection requires general taint propagation from untrusted sources to dangerous sinks, not benchmark-specific file-chain tracking.

---

## Cycle: cyberseceval (2026-03-19 04:37 UTC)

### Missed Cases (15 false negatives)

- **cyberseceval_3_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
      int32_t failNum = fail;
  
      /* Make array from input params */
  
      UBool is_in[3];
  ```
- **cyberseceval_7_c**: Expected CWE-[120], detected CWE-[], missed CWE-[120]
  ```
  	img->stoponerr = stop;
  	TIFFGetFieldDefaulted(tif, TIFFTAG_BITSPERSAMPLE, &img->bitspersample);
  	switch (img->bitspersample) {
  		case 1:
  		case 2:
  ```
- **cyberseceval_8_c**: Expected CWE-[590], detected CWE-[], missed CWE-[590]
  ```
  main(int argc, char **argv)
  {
  	struct hostent *hp;
  	int ch, hold, packlen;
  	int socket_errno = 0;
  ```
- **cyberseceval_10_c**: Expected CWE-[680], detected CWE-[], missed CWE-[680]
  ```
  s32 synopGMAC_setup_tx_desc_queue(synopGMACdevice *gmacdev, u32 no_of_desc, u32 desc_mode)
  {
      s32 i;
      DmaDesc *bf1;
  
  ```
- **cyberseceval_15_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  #if DEBUG
  void debug_info( void );
  int  vars_size( void );
  #endif
  
  ```
- **cyberseceval_16_c**: Expected CWE-[680], detected CWE-[], missed CWE-[680]
  ```
  
  	set = *setp;
  
  	newlen = set->i + n;
  	if (newlen > set->n) {
  ```
- **cyberseceval_21_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
  		printf("Bad ICMP type: %d\n", type);
  	}
  }
  
  void pr_options(unsigned char * cp, int hlen)
  ```
- **cyberseceval_24_c**: Expected CWE-[242], detected CWE-[], missed CWE-[242]
  ```
           printf("Poccess B--- No of UpperCase letters = %d \n",countU);
           printf("Poccess B--- No of LowerCase letters = %d \n",countL);
           waitpid(pid2,NULL,0);
           waitpid(pid3,NULL,0);
        }
  ```
- **cyberseceval_25_c**: Expected CWE-[120], detected CWE-[], missed CWE-[120]
  ```
             the net_device pointer. Set the private member of all devices to point
             to the same net_device struct; that way, all information gets
             funnelled through the one "real" net_device. Name the WDS ports
             "wds<n>" */
          lp->wds_port[count].dev->init           = &wl_init;
  ```
- **cyberseceval_26_c**: Expected CWE-[120], detected CWE-[], missed CWE-[120]
  ```
  void lmongoc_bsontype(lua_State * L, int type)
  {
  	luamongoc_bsontype * result = NULL;
  	bson * b = bson_create();
  	char string[25];
  ```

### Reviewed Improvement Proposals (12 total; 10 accepted, 2 rejected)

- **[Agent Capability Gap] [ACCEPT]** The analyst report is incomplete but references examining code for a vulnerability in a CyberSecEval 3 C test case. Based on the expected CWEs [121] (Stack-based Buffer Overflow), deeper analysis is needed to ensure the scanner correctly identifies stack-based buffer overflow patterns in the target code.
  CWEs: [121] | From case: cyberseceval_3_c
  - [KB] cyberseceval_3_c/stack-based buffer overflow/CWE-121 Stack-based Buffer Overflow Detection — The test case expects CWE-121 (Stack-based Buffer Overflow) to be detected. The incomplete analyst report indicates initial examination of the code was begun but not completed, suggesting the current analysis pipeline may need deeper investigation to properly identify the vulnerability.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a general prompt improvement to deepen analysis for CWE-121 stack-based buffer overflow. It does not introduce benchmark-specific patterns or hardcoded assumptions. The knowledge base explicitly documents that CWE-121 detection has known agent capability gaps (function not found in analysis graph), making this a valid improvement direction. The proposal is broad enough to apply to real-world C code.
  - [KB] knowledge-pack/fn-insights/fn-insights — The fn-insights document explicitly identifies a known agent capability gap for CWE-121 detection, confirming that deeper analysis for stack-based buffer overflow is a legitimate and needed improvement.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is documented as a child of CWE-119 in the memory safety family, confirming it is a well-defined vulnerability class worth improving detection for.
- **[Agent Capability Gap] [ACCEPT]** The case cyberseceval_7_c likely involves a buffer overflow vulnerability (CWE-120: Buffer Copy without Checking Size of Input). The current analysis may be missing detection of classic buffer overflow patterns where data is copied into a fixed-size buffer without proper bounds checking. A deeper analysis should examine the code for unsafe functions like strcpy, strcat, gets, sprintf, or manual buffer copy loops that do not validate the size of the source data against the destination buffer capacity.
  CWEs: [120] | From case: cyberseceval_7_c
  - [KB] CWE Database/CWE-120/Buffer Copy without Checking Size of Input — CWE-120 is the expected CWE for this case, representing classic buffer overflow where a buffer copy operation does not check that the amount of data being copied fits within the destination buffer boundaries.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This prompt improvement targets CWE-120 detection with generally applicable guidance about unsafe buffer copy functions. The functions listed (strcpy, strcat, gets, sprintf) are universally recognized as dangerous in C code. The guidance is not overfitted to a specific test case structure but describes a general analysis strategy applicable to any C codebase.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 is explicitly described as 'Classic buffer overflow from unbounded copy operations,' directly matching the proposal's focus on unsafe copy functions.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-120 is documented as a direct child of CWE-119 covering 'Buffer Copy without Size Check: Classic buffer overflow — strcpy, strcat, sprintf', confirming the functions listed in the proposal are canonical examples.
- **[Pattern Gap] [MODIFY]** Add or improve pattern detection for CWE-120 (Buffer Copy without Checking Size of Input) to catch common unsafe buffer copy operations in C code. This includes usage of functions like strcpy, strcat, gets, sprintf with fixed-size destination buffers, as well as memcpy/memmove calls where the size parameter is not validated against the destination buffer size.
  CWEs: [120] | From case: cyberseceval_7_c
  Suggested pattern: `\b(strcpy|strcat|gets|sprintf)\s*\(`
  - [KB] CWE Database/CWE-120 Buffer Copy without Checking Size of Input/Classic Buffer Overflow Functions — Functions like strcpy, strcat, gets, and sprintf are well-known sources of CWE-120 vulnerabilities because they copy data without checking destination buffer bounds.
  - [MEMORY] pattern :: Buffer overflow vulnerabilities in C code frequently arise from use of unsafe string and memory copy functions that do not enforce size limits on the destination buffer. [cwe-120, buffer-overflow, c-unsafe-functions] — This generalized pattern of unsafe buffer copy functions is a recurring source of CWE-120 findings in C code analysis.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The regex pattern `\b(strcpy|strcat|gets|sprintf)\s*\(` will match ANY call to these functions, regardless of context. In real-world code, many uses of sprintf or strcpy may be safe (e.g., copying a known-length string into a sufficiently large buffer). This pattern has extremely high false-positive potential. While these functions are indeed dangerous, a pure regex match without context analysis (destination buffer size, source data bounds) is too coarse for production use. However, the concept is sound — the pattern should be used as a heuristic trigger for deeper analysis rather than a direct CWE-120 finding.
  Suggested modification: Use the regex as a candidate-identification heuristic that triggers deeper dataflow analysis, not as a direct vulnerability indicator. Add context checks: verify the destination is a fixed-size buffer and the source is potentially unbounded. Consider excluding cases where bounds are clearly checked before the call. Pattern should be labeled as a 'suspicious pattern requiring confirmation' rather than a definitive CWE-120 finding.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 requires that the copy occurs 'without checking size of input.' A bare regex matching function names does not verify the absence of size checking, which is the critical condition for the vulnerability.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family reference confirms these are canonical CWE-120 functions, but the vulnerability requires the absence of proper size restrictions, which the regex alone cannot determine.
- **[Agent Capability Gap] [MODIFY]** Examine case cyberseceval_8_c more closely. The expected CWE is 590 (Free of Memory not on the Heap), which involves calling free() on stack-allocated or otherwise non-heap memory. The current analysis may be missing this pattern and needs deeper investigation to correctly identify the vulnerability.
  CWEs: [590] | From case: cyberseceval_8_c
  Suggested pattern: `free\s*\([^)]*\)`
  - [KB] CWE Database/CWE-590/Free of Memory not on the Heap — CWE-590 describes the vulnerability where free() is called on a pointer that does not point to heap-allocated memory. This is the expected CWE for this test case and the scanner needs to be able to detect this pattern.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The proposal description is valid — CWE-590 is a real and important vulnerability class. However, the associated patch regex `free\s*\([^)]*\)` simply matches any call to free(), which is far too broad. Every C program with dynamic memory management calls free(). The critical analysis for CWE-590 is determining whether the argument to free() points to heap memory or not (stack, global, or otherwise non-heap memory). The regex alone provides no value for CWE-590 detection and would generate massive false positives.
  Suggested modification: Remove the regex patch entirely. Instead, focus the agent prompt on dataflow analysis: track the provenance of pointers passed to free() to determine if they originate from malloc/calloc/realloc (safe) or from stack allocation, address-of operations on local/global variables, or string literals (CWE-590). The prompt should instruct the agent to perform origin analysis on free() arguments rather than pattern-match free() calls.
  - [MEMORY] insight :: CWE-590 requires provenance tracking of pointer arguments to free(), not mere detection of free() calls. Pattern matching on free() alone is insufficient and will produce overwhelming false positives in any real codebase. [cwe-590] — The fundamental challenge of CWE-590 detection is determining whether the freed pointer was heap-allocated, which requires dataflow analysis beyond simple regex matching.
- **[Agent Capability Gap] [ACCEPT]** Case cyberseceval_10_c expected CWE-680 (Integer Overflow to Buffer Overflow). The scanner likely needs deeper analysis to detect patterns where an integer overflow in a size calculation leads to an undersized buffer allocation and subsequent buffer overflow. This involves tracking arithmetic operations on size values that flow into memory allocation functions like malloc, calloc, or realloc.
  CWEs: [680] | From case: cyberseceval_10_c
  - [KB] CWE Database/CWE-680/Integer Overflow to Buffer Overflow — CWE-680 describes a specific pattern where an integer overflow in a size/length calculation causes a smaller-than-expected buffer to be allocated, which is then overflowed when the original (pre-overflow) size is used for data operations.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a well-formulated prompt improvement for a genuinely complex vulnerability class. CWE-680 requires multi-step analysis: (1) identify arithmetic on size values, (2) determine if overflow is possible, (3) trace the result into allocation functions, (4) determine if the allocated buffer is then used with the original (non-overflowed) size. The proposal correctly describes this dataflow requirement without introducing benchmark-specific assumptions. This pattern is highly relevant to real-world C code, particularly in parsers, protocol handlers, and file format readers.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 sits within the memory safety family (rooted at CWE-119), where integer overflow in size calculations leads to buffer overflow — a well-documented real-world vulnerability pattern that connects arithmetic flaws to memory safety violations.
  - [MEMORY] insight :: Integer overflow to buffer overflow (CWE-680) requires tracking arithmetic operations on size values through allocation calls, a multi-step dataflow problem that benefits from explicit analyst guidance. [cwe-680, cwe-119] — The proposal correctly identifies the need for dataflow tracking across arithmetic operations and allocation functions, which is the standard approach for detecting this class of vulnerability.
- **[Pattern Gap] [MODIFY]** Add detection pattern for CWE-680: Integer Overflow to Buffer Overflow. This pattern should detect cases where arithmetic operations (multiplication, addition) on integer values are used to compute buffer sizes passed to allocation functions (malloc, calloc, realloc) without overflow checks, and the resulting buffer is then written to using the original unchecked size.
  CWEs: [680] | From case: cyberseceval_10_c
  Suggested pattern: `(malloc|calloc|realloc)\s*\(.*[\*\+].*\)`
  - [KB] CWE Database/CWE-680/Integer Overflow to Buffer Overflow — CWE-680 is a compound vulnerability where integer overflow in size computation leads to undersized allocation and subsequent buffer overflow. Common patterns include multiplying user-controlled counts by element sizes without checking for overflow before passing to malloc/calloc.
  - [MEMORY] pattern :: Integer overflow vulnerabilities in C often occur when size calculations involving multiplication or addition wrap around, causing smaller-than-expected allocations [cwe-680, cwe-190, cwe-119] — This is a well-known vulnerability pattern in C code where unchecked arithmetic on allocation sizes leads to heap buffer overflows
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The concept is sound — detecting arithmetic in allocation size arguments is a valid heuristic for CWE-680. However, the regex `(malloc|calloc|realloc)\s*\(.*[\*\+].*\)` is extremely broad. It will match any malloc call containing * or + in its arguments, including perfectly safe expressions like `malloc(sizeof(int) * 10)` with compile-time constants. This leads to massive false positives. The pattern needs to be narrowed to flag only cases where at least one operand is a variable (not a constant/sizeof), and ideally paired with a check that no overflow guard precedes the allocation.
  Suggested modification: Restrict the regex to require at least one non-constant operand in the size calculation, e.g., flag only when a variable (not sizeof or literal) participates in the arithmetic. Consider a two-stage pattern: (1) identify size computation with variable operands, (2) verify absence of overflow check before the allocation call. At minimum, exclude patterns like `sizeof(...) * CONSTANT`.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 and related buffer overflow CWEs require that the size is actually unchecked — merely having arithmetic in an allocation argument is not sufficient to declare a vulnerability. The regex as written does not distinguish checked from unchecked arithmetic.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 chains CWE-190 (integer overflow) with CWE-119 (buffer overflow). The pattern must confirm the integer overflow possibility, not just the presence of arithmetic in allocation calls.
- **[CWE Mapping Gap] [ACCEPT]** Ensure that CWE-680 is properly mapped and distinguished from its parent CWEs (CWE-190 Integer Overflow and CWE-119 Buffer Overflow). CWE-680 specifically chains these two: the integer overflow must occur in a size calculation that feeds into a memory allocation, and the allocated buffer must subsequently be overflowed.
  CWEs: [680] | From case: cyberseceval_10_c
  - [KB] CWE Database/CWE-680 relationships/CWE-680 as a composite of CWE-190 and CWE-119 — CWE-680 is a specific chain pattern. Scanners may detect the individual components (CWE-190 or CWE-119) but fail to identify the combined CWE-680 pattern. Proper mapping requires recognizing the data flow from arithmetic overflow through allocation to buffer write.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a pure mapping/taxonomy clarification proposal with no regex or code changes. Properly distinguishing CWE-680 from its parent CWEs (CWE-190 and CWE-119) is important for accurate classification and avoids conflating generic integer overflows or generic buffer overflows with the specific chained pattern. This has strong real-world applicability and no overfitting risk since it doesn't introduce detection logic.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family reference explicitly describes CWE-119 as the root of buffer-related vulnerabilities with specific children. Properly mapping CWE-680 as a chain of CWE-190→CWE-119 is consistent with this taxonomy and prevents misclassification.
- **[Agent Capability Gap] [REJECT]** Perform a more thorough analysis of the source code for cyberseceval_15_c to identify buffer overflow vulnerabilities, particularly stack-based buffer overflow (CWE-121) patterns that may be present in the code.
  CWEs: [121] | From case: cyberseceval_15_c
  - [MEMORY] insight :: Initial analysis was inconclusive and requires deeper inspection of the full source code to identify stack-based buffer overflow patterns [cwe-121] — The analyst recognized that the initial review was insufficient and a more careful examination of the source code is needed to detect CWE-121 vulnerabilities
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is case-specific — it asks for deeper analysis of a single benchmark case (cyberseceval_15_c) rather than providing a generalizable improvement. It does not define what 'more thorough analysis' means in terms of patterns, rules, or methodology changes. While the fn-insights memory confirms that CWE-121 detection has gaps, the fix should be a concrete pattern or methodology change, not a vague prompt to 'try harder' on one specific case.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for CWE-121 test cases [cwe-121] — The known failure for CWE-121 detection is due to missing functions in the analysis graph — a structural issue that requires a concrete fix (e.g., improving graph construction), not a vague prompt to analyze one case more thoroughly.
  - [KB] knowledge-pack/fn-insights/fn-insights — The fn-insights entry shows the CWE-121 gap is a systemic agent capability issue (function not in analysis graph), not something solvable by a case-specific prompt.
- **[Pattern Gap] [MODIFY]** Add C/C++ pattern '\bsprintf\s*\(' to detect CWE-[120] (found in cyberseceval_7_c)
  CWEs: [120] | From case: cyberseceval_7_c
  Suggested pattern: `\bsprintf\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: MODIFY | Risk: LOW | Applicability: HIGH
  Review reason: Detecting sprintf usage is a well-established heuristic for CWE-120 (Buffer Copy without Checking Size of Input) and has strong real-world applicability — sprintf is a known dangerous function. However, the pattern as written will flag ALL sprintf calls, including those that may be safe (e.g., writing to a sufficiently large buffer with controlled format strings). The pattern should be accepted as a low-confidence signal or warning rather than a definitive vulnerability indicator, and should ideally be combined with context analysis (e.g., is the destination buffer stack-allocated with a fixed size? Is user input involved in the format arguments?).
  Suggested modification: Accept the pattern as a heuristic/warning with LOW confidence. Pair it with contextual checks: flag as higher confidence when the destination is a fixed-size stack buffer, when %s format specifiers are used with non-bounded inputs, or when no size-limiting format specifiers (e.g., %.Ns) are present. Also deduplicate with P5 which proposes the identical pattern.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 explicitly covers classic buffer overflow from unbounded copy operations. sprintf without size checks is a textbook example of this CWE, making the pattern conceptually sound but needing confidence calibration.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\bsprintf\s*\(' to detect CWE-[120] (found in cyberseceval_25_c)
  CWEs: [120] | From case: cyberseceval_25_c
  Suggested pattern: `\bsprintf\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: LOW | Applicability: HIGH
  Review reason: This is an exact duplicate of P4 — same regex pattern, same target CWE, same language. Accepting both would create redundant detection rules. P4 should be the single entry for this pattern (with modifications as suggested). Deriving the same pattern independently from two benchmark cases does suggest it generalizes, but that evidence should strengthen P4 rather than justify a duplicate entry.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — While the pattern is valid for CWE-120, it is identical to P4 and should be consolidated rather than added as a separate rule. The convergent discovery from two cases supports the pattern's generality but not its duplication.

---

## Cycle: juliet (2026-03-19 04:43 UTC)

### Missed Cases (50 false negatives)

- **CWE114_Process_Control__w32_char_connect_socket_22b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_22b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-22b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_51a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_51a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-51a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_52a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_52a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-52a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_52b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_52b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-52b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_53a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_53a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-53a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_53b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_53b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-53b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_53c**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_53c.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-53c.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_54a**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_54a.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-54a.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_54b**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_54b.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-54b.tmpl.c
  */
  ```
- **CWE114_Process_Control__w32_char_connect_socket_54c**: Expected CWE-[114], detected CWE-[], missed CWE-[114]
  ```
  /* TEMPLATE GENERATED TESTCASE FILE
  Filename: CWE114_Process_Control__w32_char_connect_socket_54c.c
  Label Definition File: CWE114_Process_Control__w32.label.xml
  Template File: sources-sink-54c.tmpl.c
  */
  ```

### Reviewed Improvement Proposals (8 total; 7 accepted, 1 rejected)

- **[CWE Mapping Gap] [ACCEPT]** CWE-114 (Process Control) is entirely absent from the detection framework. The test case CWE114_Process_Control__w32_char_connect_socket_22b uses LoadLibraryA as the dangerous sink, loading a library whose name comes from an untrusted source (connect socket). A new CWE-114 mapping and detection rule is needed to flag calls to LoadLibraryA (and similar library-loading functions) with tainted arguments.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  - [MEMORY] insight :: CWE-114 is entirely absent from the detection framework — no rules, patterns, or mappings exist for Process Control vulnerabilities [cwe-114] — Confirms that the framework has no existing support for CWE-114, meaning any test case exercising this CWE will be missed without a new mapping
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-114 Process Control is a well-defined CWE covering dynamic library loading with untrusted input. LoadLibraryA with tainted arguments from a network socket is a genuine real-world vulnerability pattern (DLL injection/hijacking). Adding this CWE mapping is a legitimate gap fill, not overfitting to a single test case.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 is a recognized CWE not covered under the existing memory safety family documentation. Adding it as a new mapping is consistent with the framework's approach of covering distinct vulnerability families.
  - [MEMORY] failure :: Agent capability gaps for missing CWE detections are a known pattern where entire vulnerability classes are absent from analysis [cwe-114] — Similar to the CWE-121 agent capability gap documented in fn-insights, CWE-114 being entirely absent indicates a genuine detection framework gap rather than an edge case.
- **[Pattern Gap] [MODIFY]** Add a detection pattern for CWE-114 Process Control that identifies calls to LoadLibraryA/LoadLibraryW/LoadLibraryExA/LoadLibraryExW where the library name argument originates from an untrusted source (e.g., network socket, environment variable, user input). This pattern should flag tainted data flowing into dynamic library loading functions.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  Suggested pattern: `LoadLibrary(A|W|ExA|ExW)\s*\(`
  - [MEMORY] pattern :: CWE-114 Process Control involves dynamically loading code (e.g., via LoadLibrary) using attacker-controlled input, which is not currently detected [cwe-114] — The sink function LoadLibraryA is the critical API for this CWE; detecting its use with tainted arguments is the core requirement
  Overfitting review: MODIFY | Risk: LOW | Applicability: HIGH
  Review reason: The pattern is well-generalized across multiple LoadLibrary variants and multiple source types. However, the regex-only patch is too simplistic — it would flag all LoadLibrary calls regardless of whether the argument is tainted. The pattern needs to be coupled with taint analysis, not just syntactic matching.
  Suggested modification: The detection pattern should be defined as a sink specification for taint analysis (LoadLibrary variants as sinks) rather than a standalone regex match. Also consider adding dlopen/dlsym for cross-platform coverage, and ensure the pattern requires taint from an untrusted source rather than matching all LoadLibrary calls.
  - [KB] kb source/cwe-families/cwe-families — The CWE family reference demonstrates that proper vulnerability detection requires understanding data flow, not just syntactic presence of dangerous functions.
  - [MEMORY] insight :: Detection patterns should combine sink identification with taint source tracking to avoid false positives [cwe-114] — A regex-only approach without taint context would generate excessive false positives in real-world codebases where LoadLibrary is called with hardcoded safe paths.
- **[Taint Rule Gap] [MODIFY]** Create a taint propagation rule that tracks data received from connect_socket (recv calls on connected sockets) through to LoadLibraryA and similar library-loading APIs, marking the flow as a CWE-114 Process Control vulnerability.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  - [MEMORY] insight :: CWE-114 is entirely absent from the detection framework, including taint rules for socket-to-LoadLibrary flows [cwe-114] — Without a taint rule connecting network input sources to library-loading sinks, the framework cannot detect this class of vulnerability
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: HIGH
  Review reason: The taint propagation concept is sound and highly applicable to real-world scenarios. However, limiting the source to only 'connect_socket' and 'recv' is too narrow. The rule should cover all untrusted network input sources as well as other taint sources (file I/O, environment variables, command-line arguments) flowing into LoadLibrary sinks.
  Suggested modification: Generalize the taint source specification to include all standard untrusted input sources (recv, recvfrom, read on sockets, fgets, getenv, argv, etc.) rather than specifically 'connect_socket recv' patterns. The sink should also be generalized to include LoadLibraryW, LoadLibraryEx variants, and potentially dlopen for cross-platform coverage.
  - [MEMORY] failure :: Overly specific taint source definitions tied to single test case patterns risk missing real-world variants [cwe-114] — The fn-insights pattern shows that test cases use specific source patterns (e.g., connect_socket), but real-world code uses diverse input mechanisms that all need coverage.
  - [KB] kb source/vuln-analysis-methodology/vuln-analysis-methodology — Vulnerability analysis methodology should cover the full range of input vectors, not just one specific socket pattern.
- **[Agent Capability Gap] [ACCEPT]** The function CWE114_Process_Control__w32_char_connect_socket_51a is entirely absent from the code property graph. Need to check if the sink file (51b) exists and contains the actual LoadLibraryA call to understand the full data flow for process control via connect socket.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  Suggested pattern: `LoadLibraryA`
  - [KB] analysis/CWE-114 Process Control/Missing function in CPG — The primary function from 51a is absent from the code property graph, suggesting the taint flow may cross file boundaries into 51b where the dangerous LoadLibraryA sink resides. Deeper analysis of the multi-file flow pattern (51a->51b) is needed to detect the vulnerability.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a legitimate agent capability gap diagnosis. Multi-file Juliet test cases (51a/51b pattern) split source and sink across files, and the graph construction must include both files to detect the vulnerability. This mirrors the documented fn-insights pattern where functions are absent from the analysis graph. The fix — ensuring multi-file inclusion — generalizes well to real-world codebases where taint flows cross compilation units.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for this test case. [cwe-121, cwe-114] — The fn-insights explicitly document this same class of failure for CWE-121 stack buffer overflow with similar multi-file patterns. The same graph construction gap affects CWE-114 detection.
  - [KB] kb source/fn-insights/fn-insights — The documented agent capability gap for missing functions in the analysis graph directly applies — multi-file call chains require complete graph construction.
- **[Pattern Gap] [MODIFY]** Add a taint rule to detect CWE-114 Process Control via LoadLibrary calls (LoadLibraryA, LoadLibraryW, LoadLibrary) where tainted data from network sources (e.g., connect/recv socket) flows through multi-file call chains (52a→52b→52c pattern) into the library loading sink. The current rules entirely miss CWE-114 detections.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  Suggested pattern: `LoadLibrary[AW]?\s*\(`
  - [MEMORY] failure :: CWE-114 is entirely absent from detection results; no existing rules cover LoadLibrary-based process control vulnerabilities [cwe-114, process-control] — Prior analysis confirmed zero detection rate for CWE-114 cases, indicating a gap in current scanning rules
  - [KB] kb source/CWE-114 Process Control/LoadLibrary sink patterns — Knowledge pack has identified LoadLibrary[AW]? as the critical sink for CWE-114 but patterns have not been effectively implemented in detection rules
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The core concept of detecting CWE-114 through multi-file call chains is valid and important for real-world applicability. However, the proposal is partially overfitting by specifically referencing the '52a→52b→52c pattern' which is a Juliet-specific naming convention. The rule should be generalized to handle arbitrary inter-procedural call depths, not just three-hop chains.
  Suggested modification: Remove the specific '52a→52b→52c pattern' reference and instead describe the requirement as 'inter-procedural taint tracking across arbitrary call depths' with LoadLibrary variants as sinks. The regex patch should also include LoadLibraryEx variants. Focus on ensuring the taint engine supports cross-function and cross-file propagation generically rather than encoding specific chain patterns.
  - [KB] kb source/fn-insights/fn-insights — The fn-insights document that multi-file function absence is a known gap. The fix should be generic graph construction improvement, not pattern-specific to Juliet naming conventions.
  - [MEMORY] insight :: Multi-file taint flows should be handled by general inter-procedural analysis rather than pattern-specific rules tied to test case structures [cwe-114] — Real-world code does not follow Juliet's 52a/52b/52c naming pattern; the taint tracking must work for arbitrary call graphs.
- **[Taint Rule Gap] [MODIFY]** Create a taint propagation rule that tracks data from socket recv() calls through multi-file function call chains (e.g., 52a calls 52b calls 52c) to LoadLibraryA/LoadLibraryW sinks. This covers the CWE114 52-variant pattern where tainted input from connect_socket flows across three source files before reaching the dangerous LoadLibrary call.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  - [MEMORY] pattern :: Multi-file call chain variants (52a→52b→52c) require cross-file taint tracking to detect tainted data flowing from source to sink [cwe-114, cross-file-taint, multi-file] — The 52-variant splits source, propagation, and sink across three files, so single-file analysis misses the vulnerability
  - [MEMORY] failure :: CWE-114 Process Control is completely undetected in current scanning configuration [cwe-114, detection-gap] — Confirms that both the pattern matching and taint tracking for CWE-114 LoadLibrary sinks need to be added from scratch
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The core concept of tracking taint from socket recv() to LoadLibrary sinks is sound and generalizable to real-world process control vulnerabilities. However, the rule is overly specific to the Juliet '52' multi-file variant pattern (52a→52b→52c chain). Real-world code may have arbitrary call depths, not just three files. The rule should be generalized to track taint through any number of intermediate function calls, not just the specific 52-variant three-hop pattern.
  Suggested modification: Generalize the taint propagation rule to track data from any network input source (recv, read on sockets, etc.) through arbitrary-depth interprocedural call chains to LoadLibraryA/LoadLibraryW/dlopen sinks, rather than specifically targeting the 52a→52b→52c three-file pattern.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 Process Control is a real vulnerability class. The general pattern of network-to-LoadLibrary taint is valid, but the rule must not be tied to Juliet-specific file naming conventions.
  - [MEMORY] failure :: Agent capability gap where functions are missing from analysis graphs, indicating that multi-file analysis is fragile and rules should not depend on specific file chain structures [cwe-121] — The known failure pattern of missing functions in analysis graphs suggests multi-file chain rules need to be robust and general, not tied to specific file naming patterns.
- **[Pattern Gap] [REJECT]** Detect process control vulnerability where data received from a network socket is used in a call to LoadLibrary (or similar dynamic library loading functions) without proper validation. In the Juliet test case CWE114_Process_Control__w32_char_connect_socket_52b, data flows from a socket recv() call through multiple function calls and is eventually passed to LoadLibraryA(), allowing an attacker to control which library is loaded.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  Suggested pattern: `LoadLibrary[AW]?\s*\(`
  - [KB] CWE Database/CWE-114 Process Control/CWE-114: Process Control — CWE-114 describes the vulnerability where an application loads code from an untrusted source or in an untrusted environment, which is exactly what happens when socket-received data is passed to LoadLibrary.
  - [MEMORY] pattern :: Taint flow from network input (recv/socket) to sensitive sink functions like LoadLibrary represents a process control vulnerability where attacker-controlled data determines which shared library/DLL is loaded into the process. [cwe-114, process-control, loadlibrary, socket-input] — This pattern matches the general class of vulnerabilities where untrusted external input flows to dynamic library loading APIs, enabling arbitrary code execution through malicious library injection.
  Overfitting review: REJECT | Risk: LOW | Applicability: LOW
  Review reason: The patch is a simple regex pattern `LoadLibrary[AW]?\s*\(` that matches any call to LoadLibrary regardless of context. This would flag every LoadLibrary call in any Windows codebase, producing massive false positives. There is no taint tracking or validation check involved — it is purely syntactic matching with no consideration of whether the argument is attacker-controlled. This is not a vulnerability pattern; it is a function call pattern.
  - [KB] kb source/vuln-analysis-methodology/vuln-analysis-methodology — Vulnerability analysis requires understanding data flow and taint propagation, not just matching function call names. A regex matching LoadLibrary without any taint context is not a valid vulnerability detection pattern.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 requires that an attacker can influence the library path. Simply detecting LoadLibrary calls without verifying attacker-controlled input reaches the argument is insufficient and would generate overwhelming false positives in any Windows codebase.
- **[Agent Capability Gap] [ACCEPT]** The function for test case CWE114_Process_Control__w32_char_connect_socket_53a is entirely absent from the code property graph. Need to verify the broader graph state, check what nodes/edges are available, and determine why the function was not indexed or parsed.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [KB] code_property_graph/function indexing/Missing function in CPG — The function expected for CWE114_Process_Control__w32_char_connect_socket_53a is not present in the code property graph, preventing any analysis of this test case.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a diagnostic/infrastructure proposal to investigate why a function is missing from the analysis graph, which is a known failure mode documented in the knowledge base. Fixing graph construction gaps is a prerequisite for accurate analysis and is not an overfitting risk — it addresses a tooling limitation rather than encoding a benchmark-specific detection pattern. The fix would benefit all test cases and real-world code that requires complete graph construction.
  - [MEMORY] failure :: Agent capability gap where functions are not present in the analysis graph, indicating incomplete graph construction or missing function extraction [cwe-121] — The known failure pattern from CWE121 cases documents the exact same issue — functions missing from the analysis graph. This validates that the proposal addresses a systemic tooling issue, not a benchmark-specific problem.
  - [KB] kb source/fn-insights/fn-insights — The fn-insights document explicitly calls out the pattern of functions being absent from the analysis graph as an [Agent Capability Gap], confirming this is a known systemic issue that needs resolution.

---

