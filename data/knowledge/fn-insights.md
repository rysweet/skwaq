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

## Cycle: cyberseceval (2026-03-19 14:37 UTC)

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

### Reviewed Improvement Proposals (8 total; 7 accepted, 1 rejected)

- **[Agent Capability Gap] [ACCEPT]** The analyst report is incomplete but references examining code for a vulnerability in a CyberSecEval 3 C test case. Based on the expected CWE-121 (Stack-based Buffer Overflow), deeper analysis is needed to detect stack buffer overflow patterns where local/stack buffers are written beyond their bounds, such as unbounded strcpy, sprintf, gets, or loop-based writes into fixed-size stack arrays.
  CWEs: [121] | From case: cyberseceval_3_c
  - [KB] cyberseceval_3_c/stack-based buffer overflow/CWE-121 Stack-based Buffer Overflow — The expected CWE for this test case is 121 (Stack-based Buffer Overflow), indicating the code contains a pattern where a stack-allocated buffer is overflowed through unsafe operations.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a generic agent prompt enhancement asking for deeper analysis of stack-based buffer overflow patterns. It targets CWE-121 which is well-established and the guidance is broad enough (strcpy, sprintf, gets, loop-based writes) to apply to real-world code, not just one benchmark case. The knowledge base confirms CWE-121 analysis gaps exist.
  - [KB] knowledge-pack/fn-insights/fn-insights — The fn-insights explicitly document an agent capability gap for CWE-121 stack-based buffer overflow detection, confirming the need for improved analysis of these patterns.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is documented as a child of CWE-119 in the memory safety family, confirming this is a legitimate and important vulnerability class to detect.
- **[Pattern Gap] [MODIFY]** Detect buffer overflow vulnerability in C code where a fixed-size buffer is used with unbounded string copy operations (e.g., strcpy) from user-controlled input without bounds checking. In cyberseceval_7_c, the code likely involves copying data into a fixed-size buffer using strcpy or similar functions, leading to CWE-120 (Buffer Copy without Checking Size of Input).
  CWEs: [120] | From case: cyberseceval_7_c
  Suggested pattern: `strcpy\s*\(\s*\w+\s*,`
  - [KB] CWE Database/CWE-120/Buffer Copy without Checking Size of Input (Classic Buffer Overflow) — CWE-120 is the expected CWE for cyberseceval_7_c. This vulnerability occurs when a program copies input data to a buffer without verifying that the data fits within the buffer boundaries, commonly through use of unsafe functions like strcpy.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The pattern `strcpy\s*\(\s*\w+\s*,` is far too broad — it would match every single use of strcpy, including safe uses where the source is known to fit. This would cause massive false positives in real-world codebases. The description says 'likely involves' which indicates speculation rather than confirmed analysis. The pattern needs to be more specific or combined with contextual checks.
  Suggested modification: The regex pattern should be expanded to also cover strcat, sprintf, and gets (as mentioned in CWE-120 guidance), and should be used as a heuristic flag rather than a definitive detection — combined with context analysis checking whether a fixed-size destination buffer is involved. Pattern could be: (strcpy|strcat|sprintf|gets)\s*\( with a requirement for contextual validation of buffer size constraints.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 explicitly covers classic buffer overflow from unbounded copy operations including strcpy, strcat, sprintf — the pattern should cover the full family, not just strcpy.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-120 is documented as 'Buffer Copy without Size Check: Classic buffer overflow — strcpy, strcat, sprintf', confirming the pattern should include multiple functions.
- **[Agent Capability Gap] [ACCEPT]** Analyze the code for CWE-590 (Free of Memory not on the Heap) vulnerability. The test case cyberseceval_8_c expects CWE-590 to be detected, which involves freeing memory that was not dynamically allocated (e.g., freeing stack variables, global variables, or invalid pointers).
  CWEs: [590] | From case: cyberseceval_8_c
  - [KB] CWE Database/CWE-590/Free of Memory not on the Heap — CWE-590 covers cases where code calls free() on a pointer that does not point to heap-allocated memory, such as stack variables or global buffers. The expected CWE for this test case is 590.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a general-purpose agent prompt enhancement for CWE-590 detection. The description provides a clear, generalizable definition of the vulnerability class (freeing stack variables, global variables, invalid pointers). This is a well-known real-world vulnerability pattern and the prompt guidance is not overly specific to one test case.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-590 falls within the memory safety family (under CWE-119 root). While not explicitly listed in the KB excerpt, it is a recognized memory management vulnerability that complements the documented memory safety family.
- **[Agent Capability Gap] [ACCEPT]** Case cyberseceval_10_c needs deeper analysis to identify CWE-680 (Integer Overflow to Buffer Overflow) patterns. The expected CWE is 680, which involves an integer overflow in a size calculation that is then used to allocate a buffer, leading to a buffer that is too small and subsequent buffer overflow when data is written to it.
  CWEs: [680] | From case: cyberseceval_10_c
  - [KB] CWE Database/CWE-680/Integer Overflow to Buffer Overflow — CWE-680 describes scenarios where an integer overflow occurs in a size/length calculation used for memory allocation (e.g., malloc), resulting in a smaller-than-expected buffer and subsequent buffer overflow. This is the expected CWE for cyberseceval_10_c.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a well-scoped agent prompt enhancement. CWE-680 is a legitimate and important real-world vulnerability class (integer overflow leading to undersized allocation). The description is generalized and not tied to specific code constructs from the benchmark. This would improve detection of a common vulnerability pattern seen in many real-world codebases.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 chains integer overflow with buffer overflow, connecting to the CWE-119 memory safety family. The parent family is well-documented in the KB, and CWE-680 is a natural extension of buffer overflow detection capabilities.
- **[Pattern Gap] [MODIFY]** Add detection pattern for CWE-680: Integer Overflow to Buffer Overflow, where a multiplication or arithmetic operation on user-controlled size values is used directly in memory allocation functions like malloc, calloc, or realloc without overflow checking.
  CWEs: [680] | From case: cyberseceval_10_c
  Suggested pattern: `(malloc|calloc|realloc)\s*\(.*[*+].*\)`
  - [KB] CWE Database/CWE-680/Integer Overflow to Buffer Overflow — CWE-680 is characterized by arithmetic operations (especially multiplication) on size values passed to allocation functions. A pattern matching allocation calls containing arithmetic operators can help detect this vulnerability class.
  - [MEMORY] pattern :: Integer overflow vulnerabilities in size calculations before buffer allocation are a common source of heap buffer overflows in C code [cwe-680, cwe-190, cwe-122] — This pattern captures the core mechanism of CWE-680 where unchecked integer arithmetic in allocation size computations leads to undersized buffers.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The regex `(malloc|calloc|realloc)\s*\(.*[*+].*\)` is too broad and would match many safe and legitimate patterns, such as `malloc(sizeof(int) * 10)` with constant values, or `calloc(n, sizeof(struct))` which is the correct two-argument form. The pattern doesn't distinguish between constant arithmetic (safe) and variable arithmetic (potentially unsafe). It would generate enormous false positive rates in real-world code.
  Suggested modification: The pattern should be refined to focus on cases where at least one operand in the arithmetic expression is a variable (not a sizeof or constant), and should exclude calloc's standard two-argument form which already handles overflow internally on many platforms. Consider a two-stage approach: (1) flag `malloc\s*\(.*\b\w+\s*[*+]\s*\w+` where operands are variables, then (2) verify no overflow check (e.g., __builtin_mul_overflow, explicit comparison) precedes the allocation.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 involves integer overflow leading to buffer overflow. The memory safety family documentation shows buffer overflows stem from improper size restrictions — a pattern matching only arithmetic in allocations without distinguishing safe constant expressions from dangerous variable expressions would not properly identify the vulnerability.
  - [MEMORY] insight :: Overly broad regex patterns for memory allocation functions match safe idiomatic C patterns like sizeof(type)*count, causing high false positive rates [cwe-680, cwe-119] — Real-world C code pervasively uses arithmetic in allocation calls for legitimate purposes; the pattern must discriminate between safe constant arithmetic and potentially overflowing variable arithmetic.
- **[CWE Mapping Gap] [ACCEPT]** Ensure CWE-680 is properly mapped and distinguished from CWE-190 (Integer Overflow) and CWE-122 (Heap Buffer Overflow). CWE-680 specifically chains an integer overflow in a size calculation to a buffer overflow via undersized allocation. The scanner should recognize this composite pattern rather than flagging only the individual components.
  CWEs: [680] | From case: cyberseceval_10_c
  - [KB] CWE Database/CWE-680 relationships/CWE-680 as a composite of CWE-190 and CWE-122 — CWE-680 is a specific chain: CWE-190 (integer overflow) -> CWE-122 (heap buffer overflow). Proper detection requires recognizing that the overflow occurs in a value subsequently used for allocation, not just any integer overflow.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-680 (Integer Overflow to Buffer Overflow) is a legitimate composite CWE that represents a real-world vulnerability chain: integer overflow in size calculation → undersized allocation → buffer overflow. Properly distinguishing this from its individual components (CWE-190, CWE-122) improves mapping precision and reflects how these vulnerabilities actually manifest. This is not overfitting to a single benchmark case but captures a well-documented, distinct vulnerability pattern.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — The CWE family reference establishes that buffer overflow CWEs have distinct children with specific semantics. CWE-680 is a recognized chain that differs from its components, justifying explicit mapping support.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family hierarchy under CWE-119 shows that buffer-related CWEs have distinct subtypes. CWE-680 as a composite pattern (integer overflow leading to buffer overflow) is a legitimate distinct entry that should be recognized separately from CWE-190 or CWE-122 alone.
- **[Agent Capability Gap] [REJECT]** The analyst report indicates a need for deeper analysis of the source file to understand the full vulnerability. Based on the case context (cyberseceval_15_c with expected CWE-121, stack-based buffer overflow), the source file likely contains a stack-based buffer overflow vulnerability that requires more careful examination to fully characterize.
  CWEs: [121] | From case: cyberseceval_15_c
  - [KB] cyberseceval/CWE-121 stack-based buffer overflow/Stack-based Buffer Overflow Analysis — The case cyberseceval_15_c expects CWE-121 (Stack-based Buffer Overflow), indicating the source file contains a vulnerability where data is written beyond the bounds of a stack-allocated buffer. Deeper analysis is needed to confirm the exact pattern and trigger conditions.
  Overfitting review: REJECT | Risk: MEDIUM | Applicability: LOW
  Review reason: This proposal is too vague to be actionable. It merely restates that 'deeper analysis is needed' without specifying what concrete change should be made to the agent prompt, what analysis capability is missing, or what pattern should be added. It provides no patch, no specific prompt modification, and no diagnostic information about why the current analysis failed. This is essentially a restatement of the problem rather than a solution.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for this test case. [cwe-121] — The known failure pattern for CWE-121 stack-based buffer overflow cases shows that the root cause is often missing function extraction from the analysis graph. A proper proposal should address graph construction or function extraction specifically, not just call for 'deeper analysis' generically.
  - [KB] knowledge-pack/fn-insights/fn-insights — The fn-insights KB explicitly documents that CWE-121 failures stem from functions not being present in the analysis graph. The proposal does not address this specific root cause and instead offers a vague suggestion for deeper analysis.
- **[Pattern Gap] [MODIFY]** Add C/C++ pattern '\bsprintf\s*\(' to detect CWE-[120] (found in cyberseceval_7_c)
  CWEs: [120] | From case: cyberseceval_7_c
  Suggested pattern: `\bsprintf\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: While sprintf is indeed a classic source of CWE-120 (Buffer Copy without Checking Size of Input) vulnerabilities, a bare pattern matching any sprintf call will produce extremely high false positive rates in real-world codebases. sprintf is used pervasively in C/C++ code and many uses are safe (e.g., writing to sufficiently sized buffers with known-length format strings). The pattern needs additional context to be useful — at minimum, it should flag sprintf as a lower-confidence finding or be combined with heuristics about buffer size and input source.
  Suggested modification: Refine the pattern to reduce false positives: (1) flag sprintf calls as informational/low-confidence unless combined with evidence of unbounded input (e.g., user-controlled format arguments or variable-length source data), or (2) pair with a secondary check that the destination buffer size is not verified. Consider pattern: '\bsprintf\s*\(\s*\w+\s*,' with a requirement that no prior bounds check or sizeof-based guard is detected for the destination buffer.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 explicitly describes 'classic buffer overflow' from unbounded copy operations. sprintf without size checking is a canonical example, but the CWE definition implies the vulnerability requires absence of size checking — not merely the presence of sprintf.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE-120 entry under Memory Safety Family specifies 'Buffer Copy without Size Check' and lists sprintf among classic examples. However, the family description emphasizes the absence of size checking as the defining characteristic, supporting the need for contextual analysis beyond mere function presence.

---

## Cycle: juliet (2026-03-19 14:43 UTC)

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

### Reviewed Improvement Proposals (8 total; 6 accepted, 2 rejected)

- **[Agent Capability Gap] [ACCEPT]** The file CWE114_Process_Control__w32_char_connect_socket_22b.c appears to be only the source/data-flow portion of a two-file test case (22a/22b pattern). Need to analyze the companion file 22a which likely contains the sink (e.g., LoadLibrary call) to confirm the full taint flow from socket source to process control sink, enabling proper CWE-114 detection.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  - [KB] Juliet test suite conventions/Multi-file test case patterns/22a/22b split-file pattern in Juliet — In the Juliet test suite, files ending in 22b typically define a global variable and a 'badSource' or 'goodSource' function that populates data (the source side), while 22a contains the main flow and sink. Both files must be analyzed together to trace the complete taint path from source to sink for CWE-114 Process Control.
  - [MEMORY] pattern :: Two-file test cases in Juliet require cross-file taint analysis; analyzing only one file misses the full vulnerability path [cwe-114, multi-file, taint-flow] — Previous analysis patterns show that split-file Juliet cases (22a/22b) need both files examined to correctly identify the vulnerability, as the source and sink reside in separate compilation units.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal correctly identifies the multi-file pattern (22a/22b) used in Juliet and recognizes that analyzing only one file is insufficient. Ensuring companion files are included in the analysis graph is a general requirement for any interprocedural taint analysis and not specific to Juliet conventions. Real-world code similarly splits source and sink across modules.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for test cases with split files [cwe-121] — The known failure pattern of functions missing from the analysis graph due to incomplete graph construction directly parallels this issue — the companion file must be included for complete analysis.
- **[CWE Mapping Gap] [ACCEPT]** Add CWE-114 (Process Control) to the scanner's CWE mapping. Currently CWE-114 is entirely absent from detection, meaning no patterns or rules exist to identify process control vulnerabilities such as dynamic library loading from untrusted sources.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  - [MEMORY] insight :: CWE-114 is entirely absent from detection — no CWE mapping, no sink patterns, no taint rules exist [cwe-114] — Prior analysis confirmed CWE-114 has zero coverage in the current scanner configuration
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-114 (Process Control) is a well-established CWE covering dynamic library loading from untrusted sources. Adding it to the scanner's CWE mapping is a foundational requirement that applies broadly to real-world applications, not just Juliet. Many real-world vulnerabilities involve loading attacker-controlled library paths.
  - [KB] kb source/cwe-families/cwe-families — The CWE family reference demonstrates the scanner already organizes detection around CWE families. CWE-114 is a distinct, recognized vulnerability class that warrants its own mapping entry, consistent with how other CWE families are handled.
- **[Pattern Gap] [MODIFY]** Add a sink pattern for LoadLibrary variants (LoadLibraryA, LoadLibraryW, LoadLibrary) which are the primary sinks for CWE-114 Process Control vulnerabilities. The pattern should match calls where untrusted data flows into the library name parameter.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  Suggested pattern: `LoadLibrary[AW]?\s*\(`
  - [MEMORY] pattern :: LoadLibrary[AW]? patterns have been proposed but never successfully implemented for CWE-114 detection [cwe-114] — Previous proposals identified LoadLibrary as the key sink for CWE-114 but implementation never completed
  - [KB] kb source/learned-patterns/LoadLibrary sink pattern for CWE-114 — The learned-patterns knowledge pack shows that LoadLibrary[AW]? patterns have been proposed for CWE-114 detection
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The regex pattern `LoadLibrary[AW]?\s*\(` is reasonable but too narrow. Real-world CWE-114 sinks include additional functions like LoadLibraryEx, dlopen (on POSIX), and potentially other dynamic loading APIs. Limiting to only LoadLibrary variants risks being Juliet-specific. The pattern should be broadened to cover the full family of dynamic library loading functions.
  Suggested modification: Extend the sink pattern to include LoadLibraryExA, LoadLibraryExW, dlopen, and other platform-specific dynamic loading APIs (e.g., dlopen on Linux). The pattern should be: `(LoadLibrary(Ex)?[AW]?|dlopen)\s*\(` at minimum, with the sink rule documenting that the first parameter (library path) is the taint-sensitive argument.
  - [KB] kb source/cwe-families/cwe-families — The CWE family reference shows that vulnerability classes should be treated comprehensively. CWE-114 covers all process control via dynamic loading, not just Windows LoadLibrary — restricting to only LoadLibrary[AW] is incomplete for real-world coverage.
- **[Taint Rule Gap] [ACCEPT]** Add a taint propagation rule for CWE-114 that tracks data flowing from network sources (e.g., connect_socket/recv) through to LoadLibrary calls. In the 51a/51b split-flow pattern, tainted data is received via socket in the 51a file and passed to the sink in the 51b companion file via function parameter.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  - [MEMORY] insight :: No taint rules exist for CWE-114; data flows from socket source in 51a to LoadLibrary sink in 51b [cwe-114] — The absence of taint rules means even if the sink pattern is added, cross-file taint from network source to LoadLibrary sink would not be tracked
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal addresses a genuine need for interprocedural taint tracking from network sources to dynamic loading sinks. The concept is general — real-world vulnerabilities commonly involve network-sourced data reaching security-sensitive sinks across function/file boundaries. The mention of 51a/51b is contextual but the underlying rule (network source → LoadLibrary sink) is broadly applicable.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for test cases with split-flow patterns [cwe-121] — The known failure of missing interprocedural analysis directly supports the need for taint propagation rules that cross file/function boundaries, which is what this proposal addresses for CWE-114.
- **[Agent Capability Gap] [REJECT]** Analyze the full vulnerability flow in CWE114_Process_Control__w32_char_connect_socket_52a to understand the taint propagation from socket source through intermediate functions to the LoadLibrary sink, ensuring proper CWE-114 detection.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  Suggested pattern: `LoadLibrary`
  - [MEMORY] insight :: CWE-114 Process Control involves loading libraries from untrusted sources, typically through LoadLibrary calls with attacker-controlled input from network sockets [cwe-114] — Prior memory indicates CWE-114 patterns involve taint flow from network sources to LoadLibrary sinks, which needs deeper analysis to confirm detection coverage
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is redundant with P1 and P4 — it describes the same multi-file analysis need and taint tracking requirement but for a specific test case (52a). It does not introduce any new pattern, rule, or capability beyond what P1 (companion file analysis) and P4 (taint propagation) already cover. Accepting this would create a per-test-case prompt pattern that is inherently Juliet-specific and does not generalize.
  - [MEMORY] insight :: Proposals that target individual test case file names without introducing new generalizable capabilities are signs of overfitting to the benchmark rather than improving general detection [cwe-114] — P5 duplicates the analysis guidance of P1 and P4 but scoped to a single test case variant (52a), providing no additional general value and risking benchmark-specific tuning.
- **[Agent Capability Gap] [ACCEPT]** The test case CWE114_Process_Control__w32_char_connect_socket_52b involves a multi-file taint flow where data received from a network socket (connect_socket) is passed through a chain of function calls (52b -> 52c -> 52d) and eventually used in a LoadLibrary call (CWE-114 Process Control). The scanner likely fails to track taint across the 52b/52c/52d file chain, resulting in a false negative. The analysis needs to follow inter-procedural taint from the socket recv() call through intermediate forwarding functions to the dangerous LoadLibraryA() sink.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  - [KB] CWE Database/CWE-114 Process Control/CWE-114: Process Control — CWE-114 covers situations where an application loads a library or code module from an untrusted source, such as user-controlled or network-derived input passed to LoadLibrary. This is the expected vulnerability in the test case.
  - [MEMORY] pattern :: Multi-file taint propagation chains (e.g., 52a->52b->52c->52d patterns in Juliet test suite) frequently cause false negatives because scanners lose track of taint across function call boundaries spanning multiple translation units. [cwe-114, inter-procedural, taint-flow] — The 52-series Juliet test cases specifically test inter-file data flow tracking, and scanners commonly fail on these due to incomplete inter-procedural analysis.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal addresses a genuine inter-procedural taint tracking gap across multi-file function call chains. The pattern of data flowing from a socket recv() through forwarding functions to a dangerous sink like LoadLibraryA() is a real-world vulnerability pattern (CWE-114). The prompt improvement is general enough — it instructs the agent to follow inter-procedural taint across file boundaries, which applies broadly to many multi-file taint scenarios, not just this specific test case. The CWE-114 mapping is correct for LoadLibrary with externally-controlled input.
  - [MEMORY] failure :: Agent capability gaps in tracking functions across multi-file call chains leading to missed vulnerabilities [cwe-114] — The known failure pattern of functions not being found in analysis graphs or taint not propagating across file boundaries is consistent with this proposal's diagnosis of the root cause.
  - [KB] kb source/fn-insights/fn-insights — The fn-insights document describes agent capability gaps where functions are not properly included in analysis graphs, which parallels the multi-file taint tracking issue described in this proposal.
- **[Taint Rule Gap] [MODIFY]** Add a taint propagation rule for the 52b->52c->52d call chain pattern in CWE114 Process Control test cases. The function in 52b receives tainted data (from socket recv in 52a) as a parameter and forwards it to the 52c function. The taint must be preserved through these intermediate forwarding functions so that when LoadLibraryA() is called in the final function (52d), the tainted argument is detected as a CWE-114 vulnerability.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  - [KB] Juliet Test Suite Documentation/Multi-file flow variants/Juliet 52-series: Data flow through multiple files — The 52-series test cases pass tainted data through a chain of functions across files (a->b->c->d). Each intermediate function simply forwards the data to the next, requiring the scanner to maintain taint across file boundaries.
  - [MEMORY] failure :: False negatives commonly occur when taint analysis does not propagate through simple parameter-forwarding functions across translation unit boundaries, especially in the Juliet 52-series patterns. [cwe-114, false-negative, inter-procedural] — This specific failure pattern matches known gaps in cross-file taint tracking where intermediate functions act as pass-through for tainted data destined for a dangerous sink like LoadLibraryA.
  Overfitting review: MODIFY | Risk: HIGH | Applicability: MEDIUM
  Review reason: The concept of ensuring taint propagation through intermediate forwarding functions is valid and broadly applicable. However, the proposal as written is overly specific to the 52b->52c->52d naming pattern, which is a Juliet benchmark convention (numbered file chain suffixes). A real-world taint rule should generalize to any chain of forwarding functions that pass parameters through without sanitization, regardless of file naming conventions.
  Suggested modification: Generalize the taint rule to propagate taint through any function that receives a parameter and passes it directly (or with trivial transformation) as an argument to another function call, rather than targeting the specific 52b/52c/52d naming pattern. The rule should be: 'When a function parameter flows directly into an argument of a callee without sanitization, propagate the taint to the corresponding parameter of the callee.'
  - [KB] kb source/fn-insights/fn-insights — The fn-insights document shows that function-level analysis gaps cause missed detections. A taint rule tied to specific Juliet naming conventions (52b/52c/52d) would not generalize to real-world code where forwarding functions have arbitrary names.
- **[Agent Capability Gap] [REJECT]** Analyze CWE114_Process_Control__w32_char_connect_socket_53a to verify the specific code path and sink function where externally-controlled input from a connect socket flows through a chain of functions (53a->53b->53c->53d) and is used in a process control operation such as LoadLibrary, confirming the expected CWE-114 mapping.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [MEMORY] pattern :: CWE-114 Process Control cases involve externally sourced data (e.g., from sockets) being passed to process control functions like LoadLibrary without proper validation, following multi-file call chains typical of Juliet test cases. [cwe-114, process-control, w32] — Memory contains well-developed understanding of CWE-114 Process Control patterns where socket-received data flows through chained function calls to a dangerous sink like LoadLibraryA/LoadLibraryW.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is essentially a duplicate of P1 but for a different numbered variant (53a instead of 52b). It addresses the exact same inter-procedural taint tracking problem with the same CWE and same sink (LoadLibrary). Adding a separate agent prompt for each numbered Juliet variant (52-series, 53-series, etc.) is classic overfitting to benchmark naming conventions. P1 already provides sufficient general guidance for the agent to handle multi-file taint chains; adding per-variant prompts adds no generalizable value.
  - [KB] kb source/fn-insights/fn-insights — The fn-insights knowledge base emphasizes the need for deeper analysis and proper graph construction rather than case-by-case enumeration. Creating individual prompts per Juliet test case variant is a benchmark-specific approach that does not translate to real-world generality.

---

## Cycle: juliet (2026-03-19 14:51 UTC)

### Missed Cases (24 false negatives)

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

### Reviewed Improvement Proposals (28 total; 5 accepted, 23 rejected)

- **[Agent Capability Gap] [ACCEPT]** The analysis graph is completely empty for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01. A deeper analysis is needed to trace taint from the connect socket source through array index usage to identify the stack-based buffer overflow vulnerability.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01
  - [KB] CWE database/CWE-121/Stack-based Buffer Overflow — The test case involves CWE-121 (Stack-based Buffer Overflow) triggered via CWE-129 (Improper Validation of Array Index) with data received from a connect socket. An empty graph indicates the analysis pipeline failed to process this case.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal directly addresses a known agent capability gap where the function is entirely absent from the analysis graph. The knowledge base explicitly documents this exact case (CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01) as a failure due to incomplete graph construction. The fix is generic — ensuring functions are properly ingested — and not overfitted to a specific code pattern.
  - [KB] knowledge-pack/fn-insights/fn-insights — The KB explicitly documents this exact test case as a failure: 'Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for this test case.'
  - [MEMORY] failure :: Function not found in analysis graph for CWE121 connect_socket_01, indicating incomplete graph construction [cwe-121] — This is a documented systemic failure in function ingestion, not a pattern-specific issue.
- **[Agent Capability Gap] [ACCEPT]** The function for test case CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02 is completely absent from the analysis graph. A deeper analysis is needed to ensure the function is parsed, included in the graph, and properly evaluated for stack-based buffer overflow via connect socket with array index validation issues.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02
  - [MEMORY] failure :: Function completely absent from the analysis graph, preventing any CWE detection from occurring. [cwe-121, missing-function] — If the function is not present in the graph, no patterns or rules can match it, leading to false negatives for CWE-121 stack-based buffer overflow.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is the same systemic graph ingestion failure as P1, applied to the _02 variant (which uses a different control flow construct but the same vulnerability pattern). The proposal correctly identifies the root cause as missing function ingestion rather than a detection logic gap. The fix generalizes to real-world scenarios where functions fail to be parsed.
  - [KB] knowledge-pack/fn-insights/fn-insights — The KB documents the same class of failure for the _01 variant, and this is the same systemic issue affecting the _02 variant with identical root cause: function not found in analysis graph.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is a well-documented child of CWE-119 representing stack-based buffer overflow. The target CWE mapping is accurate.
- **[Agent Capability Gap] [ACCEPT]** The function for test case CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03 is entirely absent from the analysis graph. The graph needs to be verified and the function needs to be analyzed for stack-based buffer overflow via connect socket with array index validation issues.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03
  - [MEMORY] failure :: Function entirely absent from the graph; graph may be empty or incomplete, preventing detection of stack-based buffer overflow patterns. [cwe-121] — The absence of the function from the analysis graph means no vulnerability detection can occur, requiring deeper analysis to ensure the function is properly parsed and analyzed.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: Same systemic graph ingestion failure as P1 and P2. The _03 variant uses a different control flow construct but the underlying issue is identical: the function was never ingested. This is a legitimate infrastructure fix that generalizes beyond Juliet.
  - [KB] knowledge-pack/fn-insights/fn-insights — The documented failure pattern for the _01 variant ('Function not found in the analysis graph, indicating incomplete graph construction') applies identically to this _03 variant.
  - [MEMORY] failure :: Systematic failure in function ingestion for CWE121 connect_socket variants [cwe-121] — The root cause is graph construction, not detection logic, making this a generalizable fix.
- **[Agent Capability Gap] [ACCEPT]** The analysis graph is completely empty for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04. No functions, data sources, or sinks were ingested. The scanner needs to re-ingest and fully analyze this test case to detect the stack-based buffer overflow vulnerability where a value received from a connect socket is used as an array index without proper validation.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04
  - [MEMORY] failure :: Empty analysis graphs indicate a failure in the ingestion pipeline — no functions, sources, or sinks were extracted, resulting in zero findings for a known-vulnerable test case. [cwe-121, ingestion-failure] — The completely empty graph means the analysis infrastructure failed to process this file, so no vulnerability detection was even attempted.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: Same systemic graph ingestion failure affecting the _04 variant. The proposal correctly identifies that no functions, data sources, or sinks were ingested, pointing to an infrastructure-level issue. The CWE-121 mapping is accurate and the fix is not overfitted to any specific code pattern.
  - [KB] knowledge-pack/fn-insights/fn-insights — The KB documents the identical failure class for the _01 variant. This is the same systemic issue: incomplete graph construction preventing any analysis.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 (Stack-based Buffer Overflow) is correctly identified as a child of CWE-119. The vulnerability pattern (socket-sourced array index without validation) is a real-world applicable scenario.
- **[Agent Capability Gap] [ACCEPT]** The analysis graph is completely empty for CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05. No functions, data sources, sinks, or findings were produced. The function was never ingested into the analysis graph and needs to be re-analyzed with proper ingestion to detect the stack-based buffer overflow via connect socket with array index validation issues.
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05
  - [MEMORY] failure :: Empty analysis graph indicates the target function was never ingested, resulting in zero findings for a known vulnerable test case. [cwe-121, missing-ingestion] — The complete absence of any graph nodes (functions, sources, sinks) means the scanner never processed this file, so the expected CWE-121 stack-based buffer overflow finding could not be generated.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: Same systemic graph ingestion failure as P1-P4. The _05 variant is affected by the identical root cause. All five proposals address the same infrastructure gap where functions in this family fail to be ingested into the analysis graph. The fix is general-purpose and not overfitted.
  - [KB] knowledge-pack/fn-insights/fn-insights — The KB explicitly documents this class of failure ('Function not found in the analysis graph, indicating incomplete graph construction') for the connect_socket family of CWE-121 test cases.
  - [MEMORY] failure :: Systematic function ingestion failure across all CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket variants [cwe-121] — The consistent absence of functions across all five variants confirms this is an infrastructure-level issue, not a detection logic problem.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: The pattern `\brecv\s*\(` simply matches any call to recv(), which is an extremely common and legitimate network API call. The vast majority of recv() calls are not stack-based buffer overflows. The actual vulnerability in these Juliet cases is that an integer received from the socket is used as an array index without validation (CWE-129), which then leads to a stack-based buffer overflow (CWE-121). Matching recv() alone has no specificity for buffer overflow detection and would produce massive false positives in any real-world codebase. Additionally, CWE-121 is about stack-based buffer overflow, not about network input per se — the recv() is merely the taint source, not the vulnerability sink.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is a stack-based buffer overflow under CWE-119 family. The vulnerability is at the point of memory access without bounds checking, not at the recv() call itself. Matching recv() conflates taint source with vulnerability sink.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for this test case. [cwe-121] — The knowledge base notes that deeper analysis is needed for these CWE129_connect_socket cases. The actual vulnerability chain involves recv → atoi → unchecked array index → stack buffer overflow. A shallow recv() pattern misses this entire chain.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Identical duplicate of P1. Matching recv() is far too broad to indicate CWE-121. Every network application uses recv(); this pattern would produce enormous false positive rates with no meaningful vulnerability detection capability.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 requires detection at the buffer access point, not at the network input source. recv() is a taint source, not the vulnerability itself.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Identical duplicate pattern to P1 and P2. Same fundamental problem: recv() is a ubiquitous network API call and matching it provides no specificity for stack-based buffer overflow detection. This is pure overfitting to the Juliet test case naming convention.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for this test case. [cwe-121] — The knowledge base explicitly identifies these connect_socket cases as needing deeper analysis. A recv() regex is not that deeper analysis.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Same duplicate pattern as P1-P3. Matching recv() for CWE-121 is an incorrect mapping of taint source to vulnerability type. Would flag virtually all networked C/C++ code as having stack buffer overflows.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is specifically about stack-based buffer overflow at the memory operation site, not about where input originates.
- **[Pattern Gap] [REJECT]** Add C/C++ pattern '\brecv\s*\(' to detect CWE-[121] (found in CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05)
  CWEs: [121] | From case: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05
  Suggested pattern: `\brecv\s*\(`
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — This deterministic heuristic proposal was grounded in the knowledge-base hit for query 'methodology' so it preserves the cited-evidence contract.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: Fifth duplicate of the same overfitting pattern. All five proposals attempt to detect CWE-121 by matching recv(), which is semantically incorrect and would produce unacceptable false positive rates in any real-world deployment.
  - [KB] knowledge-pack/fn-insights/fn-insights — The knowledge base documents that these specific Juliet cases require deeper analysis of the full vulnerability chain (recv → unchecked index → array access → stack overflow). A simple recv() pattern does not constitute that analysis.

---

## Cycle: cyberseceval (2026-03-19 15:32 UTC)

### Missed Cases (13 false negatives)

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
- **cyberseceval_31_c**: Expected CWE-[121], detected CWE-[], missed CWE-[121]
  ```
   *
   * @param level
   *     The libwebsockets log level associated with the log message. This value
   *     is ignored by this implementation of the logging callback.
   *
  ```

### Reviewed Improvement Proposals (15 total; 11 accepted, 4 rejected)

- **[Agent Capability Gap] [ACCEPT]** The analyst report is incomplete but references examining code for a vulnerability in cyberseceval_3_c context. Based on the expected CWEs [121] (Stack-based Buffer Overflow), deeper analysis is needed to identify stack-based buffer overflow patterns that the current scanner may be missing in C code samples.
  CWEs: [121] | From case: cyberseceval_3_c
  - [KB] cyberseceval_3_c/stack-based buffer overflow/CWE-121 Stack-based Buffer Overflow — The expected CWE for this case is 121 (Stack-based Buffer Overflow), indicating the code likely contains a stack buffer overflow vulnerability that needs deeper analysis to detect.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal addresses a known gap where stack-based buffer overflow functions are not being found in the analysis graph. The proposal is general — it asks for deeper analysis of CWE-121 patterns in C code, which is broadly applicable. It does not introduce any case-specific logic.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for stack-based buffer overflow test cases. [cwe-121] — The known failure pattern directly matches this proposal — the agent has a documented capability gap for CWE-121 detection, making this a valid improvement request.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-121 is a well-defined child of CWE-119 in the memory safety family, confirming that stack-based buffer overflow is a real and important vulnerability class to detect.
- **[Agent Capability Gap] [ACCEPT]** The case cyberseceval_7_c expects CWE-120 (Buffer Copy without Checking Size of Input). The code likely contains a classic buffer overflow pattern where data is copied into a fixed-size buffer without proper bounds checking. A deeper analysis is needed to ensure the scanner correctly identifies this pattern and maps it to CWE-120.
  CWEs: [120] | From case: cyberseceval_7_c
  - [KB] CWE Database/CWE-120/Buffer Copy without Checking Size of Input — CWE-120 involves copying input into a buffer without verifying that the size of the input does not exceed the buffer's capacity, leading to buffer overflow vulnerabilities. The expected CWE for this case is 120.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: CWE-120 is a common and important vulnerability class. The proposal is reasonably general — requesting improved detection of classic buffer copy without size check patterns. It is not overly specific to one test case.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 is explicitly defined as classic buffer overflow from unbounded copy operations, confirming this is a well-established vulnerability pattern worth detecting.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-120 is documented as a child of CWE-119, specifically for buffer copy without size check — strcpy, strcat, sprintf patterns.
- **[Pattern Gap] [MODIFY]** Add or improve pattern detection for buffer copy operations (e.g., strcpy, memcpy, sprintf) into fixed-size buffers without size validation, which should be flagged as CWE-120 (Buffer Copy without Checking Size of Input).
  CWEs: [120] | From case: cyberseceval_7_c
  Suggested pattern: `(strcpy|memcpy|sprintf|strcat)\s*\(`
  - [KB] CWE Database/CWE-120 Buffer Copy without Checking Size of Input/Classic Buffer Overflow via Unsafe Copy Functions — CWE-120 is specifically about buffer copy operations that do not check the size of input before copying. Functions like strcpy, memcpy, sprintf, and strcat are commonly associated with this vulnerability class when used without bounds checking.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: LOW
  Review reason: The regex pattern `(strcpy|memcpy|sprintf|strcat)\s*\(` is too broad — it will flag every use of these functions regardless of context, including safe uses (e.g., memcpy with validated sizes, sprintf with %.*s precision specifiers). This would produce massive false positives in real-world codebases. The pattern needs context-awareness, such as checking whether the destination is a fixed-size buffer and whether a size check precedes the call.
  Suggested modification: Instead of a simple regex match on function names, implement a pattern that also checks for: (1) fixed-size stack/heap buffer as destination, (2) absence of prior bounds checking on the source length, and (3) consider safe alternatives (strncpy, snprintf) as negative indicators. A pure function-name regex will generate excessive false positives.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 specifically requires that the copy occurs WITHOUT checking size of input. Simply matching the function call without verifying absence of size checking is insufficient and would overreport.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family reference notes CWE-120 is specifically about buffer copy without size check — the 'without size check' part is critical context that the proposed regex ignores.
- **[CWE Mapping Gap] [ACCEPT]** Ensure that buffer overflow patterns involving unchecked copy operations are mapped to CWE-120 specifically, not just the parent CWE-119. CWE-120 is the more precise classification for buffer copy without checking size of input, and the scanner should prefer this specific CWE when the vulnerability involves a copy operation into a fixed-size buffer.
  CWEs: [120] | From case: cyberseceval_7_c
  - [KB] CWE Hierarchy/CWE-119 vs CWE-120/CWE-120 as child of CWE-119 — CWE-120 is a child of CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer). When a buffer overflow specifically involves a copy operation without size checking, CWE-120 is the more precise and appropriate classification. The ground truth expects CWE-120 for this case.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a sound CWE mapping refinement. Preferring the more specific child CWE-120 over the generic parent CWE-119 when the vulnerability pattern clearly involves an unbounded copy operation is consistent with CWE best practices and improves precision. This is broadly applicable to real-world scanning.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family hierarchy explicitly shows CWE-120 as a child of CWE-119, specifically for buffer copy without size check. Using the more specific CWE when the pattern matches is standard practice.
  - [KB] cwe/CWE-120/CWE-120 Buffer Copy without Checking Size of Input — CWE-120 has a clear and well-defined scope — classic buffer overflow from unbounded copy operations — making it a precise mapping target when copy operations are involved.
- **[Ground Truth Issue] [REJECT]** Case cyberseceval_8_c expects CWE-590 (Free of Memory not on the Heap) but without seeing the specific code and full analysis, this appears to be the correct classification for code that frees stack or static memory. The ground truth CWE-590 should be verified against the actual code pattern.
  CWEs: [590] | From case: cyberseceval_8_c
  - [MEMORY] insight :: CWE-590 involves freeing memory that was not dynamically allocated on the heap, such as stack variables or static memory passed to free() [cwe-590] — The expected CWE-590 for cyberseceval_8_c indicates code that calls free() on non-heap memory, which is a specific memory management vulnerability pattern
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is essentially speculative — it acknowledges not having seen the code and merely restates the ground truth expectation without providing any actionable improvement. There is no concrete change proposed, no pattern to add, and no mapping to fix. It is a placeholder that does not advance scanner capability. Additionally, proposing changes based on unseen code risks overfitting to a ground truth label that may itself be incorrect.
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — Proper vulnerability analysis methodology requires examining actual code before making classification decisions. This proposal explicitly admits the code was not analyzed, making it methodologically unsound.
- **[Pattern Gap] [MODIFY]** Add detection pattern for CWE-590: Free of Memory not on the Heap. This pattern should detect cases where free() is called on stack-allocated variables, static variables, or other non-heap memory.
  CWEs: [590] | From case: cyberseceval_8_c
  Suggested pattern: `free\s*\(\s*&\w+\s*\)`
  - [MEMORY] pattern :: CWE-590 commonly manifests when a pointer to a stack variable (often obtained via address-of operator) is passed to free(), or when a pointer that was not obtained from malloc/calloc/realloc is freed [cwe-590, free, heap] — A common pattern for CWE-590 is calling free() with the address of a local/stack variable, which can be detected by looking for free(&variable) patterns
  Overfitting review: MODIFY | Risk: HIGH | Applicability: LOW
  Review reason: The regex `free\s*\(\s*&\w+\s*\)` is too narrow and simultaneously too broad. It only catches `free(&var)` which is one specific syntactic form, but misses cases like freeing a stack array by name (e.g., `char buf[10]; free(buf);`) or freeing via an intermediate pointer assigned from a stack address. At the same time, `&var` could legitimately point to a heap-allocated struct member in some contexts. The pattern is overfitted to one specific case structure rather than the general CWE-590 vulnerability class.
  Suggested modification: Expand the pattern to a multi-step analysis: (1) identify variables that are stack-allocated, static, or global, (2) track whether their addresses or names flow into free() arguments. A pure regex approach is insufficient for CWE-590; this should be a flow-based rule that checks the allocation origin of the pointer being freed, not just syntactic matching of `&`.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-590 relates to memory safety and requires understanding the allocation origin of memory being freed. A simple syntactic regex cannot reliably distinguish heap from non-heap memory, necessitating deeper analysis as described in the memory safety family guidance.
  - [MEMORY] insight :: Regex-only patterns for memory safety vulnerabilities tend to produce high false positive rates and miss many real-world variants because the vulnerability depends on data flow (allocation source) rather than syntax alone. [cwe-590, cwe-119] — Memory safety CWEs require tracking allocation origins through data flow, not just pattern-matching syntax at the free() call site.
- **[Agent Capability Gap] [ACCEPT]** Perform deeper analysis on cyberseceval_8_c to confirm the CWE-590 classification. Need to trace memory allocation and deallocation paths to verify that a free() call targets non-heap memory (stack, static, or global variables).
  CWEs: [590] | From case: cyberseceval_8_c
  - [KB] cwe_database/CWE-590/Free of Memory not on the Heap — CWE-590 specifically covers the case where the program calls free() on a pointer to memory that was not allocated with associated heap allocation functions such as malloc(), calloc(), or realloc()
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a sound methodological improvement. Tracing allocation and deallocation paths is the correct approach for confirming CWE-590. The proposal is case-driven but the analytical methodology (trace memory allocation origins) generalizes well to all CWE-590 scenarios.
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — The methodology guidance supports deeper analysis to confirm vulnerability classifications. Tracing allocation and deallocation paths aligns with proper vulnerability analysis methodology.
  - [MEMORY] failure :: Function not found in analysis graph indicates incomplete analysis can lead to missed or misclassified vulnerabilities. Deeper analysis prompts help ensure thorough coverage. [cwe-121] — The fn-insights memory shows that incomplete analysis (functions missing from graph) causes classification failures, supporting the need for deeper analysis prompts.
- **[Pattern Gap] [MODIFY]** Detect CWE-680 (Integer Overflow to Buffer Overflow) patterns where an integer multiplication or arithmetic operation is used to compute a buffer size for memory allocation, potentially leading to an undersized allocation and subsequent buffer overflow.
  CWEs: [680] | From case: cyberseceval_10_c
  Suggested pattern: `(malloc|calloc|realloc|alloca)\s*\(.*\*.*\)`
  - [KB] CWE Database/CWE-680/Integer Overflow to Buffer Overflow — CWE-680 specifically describes the scenario where an integer overflow in a size calculation leads to allocation of a smaller-than-expected buffer, which is then overflowed during use. This pattern targets arithmetic in allocation size arguments.
  Overfitting review: MODIFY | Risk: HIGH | Applicability: LOW
  Review reason: The regex `(malloc|calloc|realloc|alloca)\s*\(.*\*.*\)` is extremely broad and will match virtually every calloc call (which inherently takes two arguments multiplied internally) and any malloc call with a size computation involving multiplication — many of which are perfectly safe (e.g., `malloc(sizeof(int) * 10)` with compile-time constants). This will generate massive false positives in real codebases. The pattern is simultaneously overfitted to the specific case structure while being too noisy for production use.
  Suggested modification: The pattern should be gated on whether the multiplication operands include user-controlled or runtime-variable values, and should exclude compile-time constant expressions. Consider: (1) Flag only when at least one operand in the multiplication is derived from external input or a non-constant variable, (2) Exclude calloc since it handles the two-argument multiplication differently, (3) Require absence of overflow checks (e.g., no preceding comparison or safe_multiply wrapper).
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 is a specific pattern within the memory safety family where integer overflow leads to buffer overflow. Detection requires understanding data flow (whether the integer values are attacker-controlled) rather than just syntactic presence of multiplication in allocation calls.
  - [MEMORY] insight :: Allocation size computations involving compile-time constants are safe and should not be flagged. CWE-680 requires that the arithmetic overflow be reachable with attacker-influenced values. [cwe-119, cwe-680] — The vulnerability requires attacker influence on the arithmetic operands; a purely syntactic match on multiplication in allocations will be overwhelmingly false-positive.
- **[Agent Capability Gap] [ACCEPT]** Perform deeper taint analysis on case cyberseceval_10_c to trace integer values used in memory allocation size computations, checking whether user-controlled or unchecked integer arithmetic could overflow before being passed to malloc/calloc/realloc, resulting in an undersized buffer (CWE-680).
  CWEs: [680] | From case: cyberseceval_10_c
  - [MEMORY] insight :: Integer overflow vulnerabilities in buffer size calculations are a common source of exploitable memory corruption bugs. The expected CWE-680 for this case indicates the code contains an integer overflow that directly impacts a buffer allocation size. [cwe-680, integer-overflow, buffer-overflow] — The expected CWE for cyberseceval_10_c is 680, indicating the code likely contains an integer overflow in a size calculation that leads to a buffer overflow. Deeper analysis is needed to identify the specific arithmetic operation and allocation call involved.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is the correct analytical approach for CWE-680. Taint analysis from user-controlled inputs through arithmetic operations into allocation sizes is the proper methodology. The prompt is specific enough to guide analysis but general enough to apply to any CWE-680 scenario.
  - [KB] knowledge-pack/vuln-analysis-methodology/vuln-analysis-methodology — Taint analysis tracing user-controlled values through arithmetic into allocation sizes aligns with proper vulnerability analysis methodology for integer-overflow-to-buffer-overflow chains.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 sits in the memory safety family and involves a chain from integer overflow to buffer overflow. Proper detection requires tracing data flow from inputs through arithmetic to allocations, which this prompt correctly requests.
- **[Taint Rule Gap] [ACCEPT]** Add a taint propagation rule that tracks integer values through arithmetic operations (especially multiplication) into memory allocation size parameters. When an unchecked multiplication result flows into malloc/calloc/realloc size arguments, flag as potential CWE-680.
  CWEs: [680] | From case: cyberseceval_10_c
  - [KB] CWE Database/CWE-680 Detection/Taint tracking for integer overflow to buffer overflow — CWE-680 requires tracking how integer values are computed and then used as allocation sizes. A taint rule connecting arithmetic operations to allocation functions enables detection of cases where overflow in the size computation leads to undersized buffers.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a well-designed taint propagation rule that addresses CWE-680 at the semantic level rather than syntactic level. Tracking integer taint through arithmetic into allocation sizes is the correct approach and generalizes well across codebases. The rule correctly focuses on 'unchecked' multiplication, implying it should recognize when overflow guards are present.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-680 requires tracking the flow from integer arithmetic to memory allocation. A taint rule that propagates through arithmetic operations into allocation size parameters directly models this vulnerability chain within the memory safety family.
  - [MEMORY] insight :: Flow-based and taint-based rules generalize much better than regex patterns for vulnerabilities that depend on data provenance and the absence of validation checks. [cwe-680, cwe-119] — Taint-based detection correctly models the CWE-680 attack chain and avoids the high false-positive rate of purely syntactic approaches.

---

## Cycle: juliet (2026-03-19 15:37 UTC)

### Missed Cases (10 false negatives)

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

### Reviewed Improvement Proposals (11 total; 9 accepted, 2 rejected)

- **[Pattern Gap] [REJECT]** Add a new pattern to detect Process Control (CWE-114) vulnerabilities where data received from a network socket (connect_socket) flows into LoadLibrary calls via companion 'b' files in the Juliet test suite. The sink function LoadLibraryA/LoadLibraryW in w32 char connect_socket variants (e.g., CWE114_Process_Control__w32_char_connect_socket_22b) is not currently detected.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  Suggested pattern: `LoadLibrary[AW]\s*\(`
  - [MEMORY] pattern :: Known pattern gap for CWE-114 Process Control where tainted data from network sockets flows into LoadLibrary calls, particularly in Juliet companion 'b' files [cwe-114, process-control, LoadLibrary] — Memory confirms this is a known pattern gap where LoadLibrary sink functions receiving socket-sourced data are not being detected
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is overfitted to Juliet-specific test structure (companion 'b' files, specific naming conventions like '22b'). The pattern itself (LoadLibrary[AW]) is too narrow — it only covers two variants. More importantly, this is a subset of P4 which handles the same sink detection more comprehensively. The Juliet-specific scoping ('companion b files') has no real-world meaning.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-114 is not in the documented CWE family reference, but the pattern description is specifically tied to Juliet naming conventions (22b companion files) rather than general vulnerability patterns.
  - [MEMORY] insight :: Proposals that reference Juliet-specific file naming conventions (companion a/b files, numbered variants) are overfitted to the benchmark and do not generalize to real-world codebases. [cwe-114] — The proposal explicitly references 'companion b files' and Juliet naming conventions, indicating benchmark-specific overfitting.
- **[Taint Rule Gap] [MODIFY]** Add a taint propagation rule that tracks data received from connect_socket through recv() calls to LoadLibraryA/LoadLibraryW sink functions across translation units (companion 'a' and 'b' files). The taint source is recv() on a connected socket and the sink is LoadLibrary[AW].
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  - [MEMORY] pattern :: Known pattern gap for CWE-114 Process Control where tainted data from network sockets flows into LoadLibrary calls [cwe-114, taint-analysis, connect-socket] — Memory confirms the need for taint tracking from socket recv() through to LoadLibrary calls across companion files
  - [KB] CWE Database/CWE-114 Process Control/Process Control via LoadLibrary — CWE-114 specifically covers cases where an attacker can influence the library loaded by LoadLibrary, which is the exact pattern in w32_char_connect_socket variants
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The core idea of tracking taint from recv() to LoadLibrary is sound and real-world applicable. However, the framing around 'companion a and b files' and 'connect_socket' is Juliet-specific. The taint rule should be generalized to track any network input source to process control sinks, with inter-procedural analysis as a general capability rather than specific to Juliet file pairs.
  Suggested modification: Remove references to 'companion a and b files' and 'connect_socket'. Generalize to: taint propagation from network input functions (recv, recvfrom, read on sockets, etc.) to process control sinks (LoadLibrary variants, dlopen) with general inter-procedural tracking, not limited to specific translation unit patterns.
  - [KB] knowledge-pack/fn-insights/fn-insights — The knowledge base documents issues with cross-function analysis (connect_socket patterns). The taint rule concept is valid but should not be scoped to Juliet-specific file structures.
  - [MEMORY] pattern :: Taint propagation rules should be defined generically from source categories to sink categories, not tied to specific benchmark file organization patterns. [cwe-114] — Inter-procedural taint tracking is a general need, but framing it around Juliet's a/b file convention is overfitting.
- **[CWE Mapping Gap] [ACCEPT]** Add CWE-114 (Process Control) to the CWE catalog. CWE-114 is currently entirely absent from detection capabilities, meaning any vulnerability where attacker-controlled data flows into process control functions like LoadLibraryA/LoadLibraryW/dlopen cannot be identified.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  - [MEMORY] pattern :: CWE-114 Process Control is absent from the CWE catalog and has no sink patterns or taint rules defined, causing complete detection failure for this vulnerability class [cwe-114, missing-cwe] — Prior analysis extensively documented that CWE-114 is not in the detection catalog, which is the root cause of missed detections
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: Adding CWE-114 to the detection catalog is a legitimate capability gap. CWE-114 (Process Control) is a real CWE with real-world applicability — attackers controlling library loading paths is a well-known attack vector (DLL injection, library hijacking). This proposal is not overfitted; it addresses a genuine missing CWE category.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family reference does not include CWE-114, confirming it is genuinely absent from current capabilities. Adding it is a structural improvement, not benchmark-specific.
  - [MEMORY] insight :: CWE catalog additions that cover well-established vulnerability classes with clear real-world attack scenarios are legitimate improvements. [cwe-114] — CWE-114 covers DLL injection and library hijacking which are common real-world attack patterns.
- **[Pattern Gap] [ACCEPT]** Create sink patterns for process control functions: LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW (Windows) and dlopen (POSIX). These functions load dynamic libraries and when called with attacker-controlled arguments represent CWE-114 Process Control vulnerabilities.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  Suggested pattern: `\b(LoadLibrary[AW]|LoadLibraryEx[AW]|dlopen)\s*\(`
  - [MEMORY] pattern :: No sink patterns exist for LoadLibrary/dlopen family functions, which are the critical sinks for CWE-114 Process Control vulnerabilities [cwe-114, sink-pattern] — The actual sink in the test case is LoadLibraryA() called in the 51b inter-procedural file with data received from recv()
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a well-generalized proposal that covers both Windows (LoadLibrary variants) and POSIX (dlopen) process control sinks. The function list is comprehensive and represents real-world dangerous sinks. The regex pattern is reasonable. This is not overfitted to Juliet — these are universally recognized dangerous functions.
  - [KB] knowledge-pack/cwe-families/cwe-families — The proposal follows the same pattern as existing CWE family definitions — identifying specific dangerous functions as sinks for a CWE category. This is a standard, generalizable approach.
  - [MEMORY] pattern :: Sink pattern definitions that enumerate well-known dangerous API functions across platforms (Windows + POSIX) generalize well to real-world code. [cwe-114] — LoadLibrary and dlopen are universally recognized as security-sensitive functions when called with attacker-controlled input.
- **[Taint Rule Gap] [MODIFY]** Add taint propagation rules connecting network source functions (recv, recvfrom, read on sockets) to process control sink functions (LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW, dlopen). The taint must propagate inter-procedurally across translation units (e.g., from 51a source file to 51b sink file via function parameter passing).
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  - [MEMORY] pattern :: No taint rules connect network sources (recv) to process control sinks (LoadLibraryA), and inter-procedural taint propagation across 51a/51b file boundaries is required [cwe-114, taint-rule, inter-procedural] — The vulnerability pattern involves recv() in 51a reading socket data into a buffer, which is then passed as a parameter to a function in 51b that calls LoadLibraryA() with that buffer
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The core taint source-to-sink mapping is excellent and well-generalized — recv/recvfrom to LoadLibrary/dlopen is a real attack pattern. However, the explicit mention of '51a source file to 51b sink file' is Juliet-specific. Inter-procedural taint tracking should be a general capability requirement, not framed around Juliet's file numbering scheme. Also, the taint sources should be broader (e.g., include getenv, command-line args, file reads) since CWE-114 is not limited to network inputs.
  Suggested modification: Remove Juliet-specific references ('51a source file to 51b sink file'). Broaden taint sources beyond network functions to include all attacker-controllable inputs (environment variables, command-line arguments, file reads, registry values). State inter-procedural tracking as a general requirement without referencing specific benchmark file organization.
  - [KB] knowledge-pack/fn-insights/fn-insights — The knowledge base documents inter-procedural analysis gaps generally. The taint rule should be framed as a general inter-procedural capability, not tied to specific Juliet file pairs.
  - [MEMORY] insight :: CWE-114 vulnerabilities in real-world code often involve environment variables or configuration files as sources, not just network sockets. Limiting to network sources reduces real-world coverage. [cwe-114] — Overly narrow source specification reduces real-world applicability of the taint rule.
- **[Pattern Gap] [MODIFY]** Add detection pattern for CWE-114 Process Control via LoadLibraryA/LoadLibraryW calls with tainted input. The sink function LoadLibrary[AW] is used in test cases like CWE114_Process_Control__w32_char_connect_socket_52a where data from a socket (connect_socket) flows into a LoadLibrary call, allowing an attacker to control which library is loaded.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  Suggested pattern: `LoadLibrary[AW]\s*\(`
  - [MEMORY] pattern :: CWE-114 Process Control is entirely absent from current detection capabilities. The sink pattern LoadLibrary[AW] has been identified in prior analysis cycles as the critical sink for this CWE. [cwe-114, process-control, LoadLibrary] — Prior analysis cycles have confirmed that LoadLibraryA/LoadLibraryW are the key sink functions for CWE-114 Process Control, and this CWE has zero detection coverage currently.
  - [MEMORY] insight :: Test cases for CWE-114 follow a pattern where tainted data (e.g., from network sockets) flows through helper functions and is ultimately passed to LoadLibraryA or LoadLibraryW, representing attacker-controlled library loading. [cwe-114, taint-flow, connect_socket] — The taint flow from connect_socket source to LoadLibrary sink is the canonical pattern for CWE-114 in the Juliet test suite, and detecting this flow requires recognizing LoadLibrary as a sensitive sink.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The regex pattern `LoadLibrary[AW]\s*\(` alone is a pure syntactic match that would flag every LoadLibrary call regardless of whether the argument is tainted. In real-world code, LoadLibrary is commonly called with hardcoded or trusted strings, so a pattern-only approach without taint context will produce massive false positives. The pattern itself is generalizable (LoadLibrary with tainted input is indeed CWE-114), but needs to be conditioned on taint reaching the argument.
  Suggested modification: The pattern should be used as a sink definition within a taint analysis framework, not as a standalone regex detection. Mark LoadLibrary[AW] as a CWE-114 sink and only flag when the first argument carries taint from an untrusted source. Do not flag calls with constant/hardcoded library paths.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 is a distinct process control weakness; the detection must ensure taint-driven context rather than pure syntactic matching to avoid overfitting to Juliet test case structures.
- **[Taint Rule Gap] [ACCEPT]** Add a taint sink rule for LoadLibraryA and LoadLibraryW functions. Any tainted data flowing into the first argument of these functions should be flagged as CWE-114 Process Control, as it allows an attacker to influence which dynamic library is loaded into the process.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  - [MEMORY] failure :: CWE-114 has been consistently missed because LoadLibraryA/LoadLibraryW are not registered as taint sinks in the current analysis rules. [cwe-114, missing-sink, LoadLibrary] — The absence of LoadLibrary as a recognized taint sink is the root cause of zero detection for CWE-114 Process Control vulnerabilities.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a well-scoped taint sink rule that correctly identifies LoadLibraryA/LoadLibraryW as sinks for CWE-114 when the first argument is tainted. It is not overfitted to Juliet-specific patterns—LoadLibrary with attacker-controlled input is a genuine CWE-114 vulnerability in real-world Windows applications. The rule is properly conditioned on taint flow rather than syntactic matching.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 Process Control is a recognized vulnerability family, and LoadLibrary with untrusted input is the canonical Windows example of this weakness.
- **[Agent Capability Gap] [MODIFY]** The scanner fails to detect CWE-114 (Process Control) in test case CWE114_Process_Control__w32_char_connect_socket_52b. This likely involves a multi-file taint flow (indicated by the '52b' suffix pattern) where data received from a connect socket is passed through a chain of functions and eventually used in a process control operation (e.g., LoadLibrary). The scanner needs deeper inter-procedural analysis across the 52a/52b/52c/52d file chain to track tainted data from socket input to dangerous library-loading sinks.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  - [KB] Juliet Test Suite/CWE-114 Process Control/Multi-file taint propagation pattern (52b suffix) — The '52b' suffix in Juliet test cases indicates a multi-file data flow pattern where tainted data is passed through intermediate functions across files (52a->52b->52c->52d). The scanner likely loses track of the taint across file boundaries.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: HIGH
  Review reason: The core need for inter-procedural taint analysis across file boundaries is valid and applicable to real-world codebases. However, the proposal is overly specific to the Juliet naming convention (52a/52b/52c/52d pattern). The prompt should be generalized to improve cross-file inter-procedural taint tracking rather than referencing specific Juliet file naming patterns.
  Suggested modification: Reframe the agent prompt to focus on general inter-procedural taint tracking across translation units and call chains, without referencing Juliet-specific file naming conventions like '52a/52b/52c/52d'. The improvement should be: 'Ensure taint propagation is maintained across function call boundaries spanning multiple files, particularly when data is passed as a parameter through intermediate forwarding functions to eventually reach a sensitive sink.'
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction [cwe-121] — Similar inter-procedural analysis gaps have been observed in other CWE families where functions in multi-file chains are missing from the analysis graph. The underlying issue is general graph construction completeness, not specific to CWE-114.
- **[Taint Rule Gap] [REJECT]** Add taint propagation rules for the CWE114 52-series multi-file chain pattern where socket-received data flows through intermediate 'b' functions. The tainted char buffer received via connect_socket in the 52a file is passed as a parameter to a function in 52b, which forwards it to 52c, and ultimately to 52d where it reaches a LoadLibrary sink. Each intermediate function simply passes the data along, and the scanner must maintain taint across these call boundaries.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  - [MEMORY] pattern :: Multi-file taint flow patterns in Juliet test suite frequently cause false negatives because scanners lose taint tracking across function call boundaries spanning multiple files. [cwe-114, multi-file-taint, false-negative] — This is a known pattern where inter-procedural taint analysis across files is required to detect the vulnerability. The 52-series specifically tests 4-deep call chains across separate compilation units.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is heavily overfitted to Juliet's specific 52-series multi-file test pattern (52a→52b→52c→52d). Real-world code does not follow this naming convention or this exact chain structure. The underlying need (inter-procedural taint propagation through pass-through functions) is valid but should be addressed as a general taint propagation capability, not as a pattern-matched rule for a specific Juliet test case series.
  - [KB] kb source/vuln-analysis-methodology/vuln-analysis-methodology — Vulnerability analysis methodology emphasizes general principles; encoding Juliet-specific file chain patterns (52a/b/c/d) as taint rules overfits to benchmark structure rather than addressing the general inter-procedural taint tracking problem.
- **[Agent Capability Gap] [MODIFY]** Investigate why CWE-114 (Process Control) is not being detected in test case CWE114_Process_Control__w32_char_connect_socket_53a. This likely involves a multi-file taint flow (53a/b/c/d pattern) where a string received from a network socket is passed through a chain of function calls and eventually used in a LoadLibrary or similar process control function. The analyzer needs to trace taint across at least 4 files in the call chain.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [KB] Juliet Test Suite/CWE-114 Process Control/CWE114 Process Control w32 char connect socket 53a — This is a known Juliet test case for CWE-114 where data flows from a socket source through a multi-file call chain (53a->53b->53c->53d) and is used in a dangerous process control function like LoadLibrary. The expected CWE is 114.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: HIGH
  Review reason: This is essentially the same issue as P3 but for a different Juliet test series (53 vs 52). The underlying problem—inter-procedural taint tracking across multiple files—is real and important. However, submitting separate per-test-case investigation prompts overfits to Juliet structure. This should be consolidated with P3 into a single generalized improvement for cross-file taint propagation.
  Suggested modification: Consolidate with P3 into a single generalized agent prompt: 'Improve inter-procedural taint analysis to propagate taint through chains of pass-through function calls across multiple translation units, ensuring that data originating from untrusted sources (e.g., network sockets) is tracked to sensitive sinks (e.g., LoadLibrary, system, exec) regardless of the number of intermediate forwarding functions.'
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction [cwe-121] — The same class of inter-procedural analysis gap was observed in CWE-121 cases where multi-file function chains were not fully captured in the analysis graph, confirming this is a systemic issue not specific to any one CWE or Juliet series.

---

## Cycle: juliet (2026-03-19 15:53 UTC)

### Missed Cases (10 false negatives)

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

### Reviewed Improvement Proposals (8 total; 6 accepted, 2 rejected)

- **[Pattern Gap] [REJECT]** Detect CWE-114 Process Control vulnerability where data received from a network socket is used in a LoadLibrary call without validation. In the test case CWE114_Process_Control__w32_char_connect_socket_22b, a character buffer filled from a connect socket is passed to LoadLibraryA, allowing an attacker to control which library is loaded.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_22b
  Suggested pattern: `recv\s*\(.*\).*LoadLibrary[AW]?\s*\(`
  - [KB] CWE Database/CWE-114 Process Control/CWE-114: Process Control — CWE-114 covers situations where an attacker can influence the name or path of a library that is dynamically loaded, leading to execution of attacker-controlled code. The pattern of receiving data from a socket and passing it to LoadLibrary is a classic instance of this weakness.
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: The regex pattern `recv\s*\(.*\).*LoadLibrary[AW]?\s*\(` is heavily overfitted to the Juliet test case structure. In real-world code, recv and LoadLibrary will almost never appear on the same line or in a pattern matchable by a single-line regex. Real vulnerabilities involve multi-statement, multi-function, and often multi-file data flows. This pattern would miss virtually all real-world CWE-114 instances while being tailored to synthetic benchmarks.
  - [KB] knowledge-pack/cwe-families/cwe-families — CWE-114 requires taint tracking from source to sink across code boundaries, not a single-line regex match. The CWE family reference underscores that proper vulnerability detection needs understanding of data flow, not syntactic co-occurrence.
  - [MEMORY] failure :: Juliet multi-file patterns require cross-file taint analysis, not regex matching [cwe-114] — The fn-insights KB entry demonstrates that single-function/single-line analysis misses real vulnerability patterns, especially those spanning multiple files or functions.
- **[Agent Capability Gap] [ACCEPT]** Need to examine the sink file (CWE114_Process_Control__w32_char_connect_socket_51b.c) to understand the full data flow from source (51a) to sink (51b) for the CWE-114 Process Control vulnerability. The 51a file likely reads data from a network socket and passes it to a function in 51b that uses it in a process control operation such as LoadLibrary. Without analyzing the sink file, the complete taint path cannot be verified.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_51a
  - [KB] Juliet Test Suite/CWE-114 Process Control/Multi-file flow pattern (51a/51b) — The Juliet 51a/51b pattern splits source and sink across two files: 51a reads tainted data (e.g., from a connect socket) and passes it via a function call to 51b, which performs the dangerous operation (e.g., LoadLibrary). Both files must be analyzed to map the complete vulnerability flow.
  - [MEMORY] pattern :: Multi-file taint flows in Juliet test cases require analyzing both the source file (a) and sink file (b) to correctly identify the vulnerability and ensure CWE mapping is accurate. [cwe-114, multi-file-flow, process-control] — Previous analysis of similar Juliet split-flow patterns shows that incomplete analysis of only the source file leads to missed or incorrect CWE mappings. The sink file contains the critical LoadLibrary or similar process control call that confirms CWE-114.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This is a well-scoped agent prompt improvement that addresses a genuine capability gap: the need for cross-file analysis. It doesn't introduce any overfitting risk because it asks the agent to follow data flow across compilation units, which is a general-purpose improvement applicable to any multi-file vulnerability pattern. The proposal correctly identifies that 51a/51b split patterns require examining both files.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for multi-file test cases [cwe-121] — The fn-insights KB documents a known failure mode where functions in sink files are absent from the analysis graph. This proposal directly addresses the same class of problem for CWE-114 cases.
- **[CWE Mapping Gap] [ACCEPT]** Add CWE-114 (Process Control) to the scanner's CWE mapping. CWE-114 is entirely absent from current detection capabilities. It covers scenarios where untrusted input determines which code or library is loaded at runtime, typically via LoadLibrary/dlopen with user-controlled paths.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  - [KB] cwe-families/CWE-114/Process Control: Untrusted input determines which code/library is loaded — Knowledge base explicitly documents CWE-114 with detection signals including LoadLibrary() and dlopen() with user-controlled paths, confirming it is a recognized CWE family that should be mapped.
  - [MEMORY] failure :: CWE-114 is entirely absent from detection — no CWE mapping, no sink patterns, no taint rules exist [cwe-114] — Prior analysis confirmed zero detection coverage for CWE-114, making this a critical gap.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: Adding CWE-114 to the CWE mapping is a prerequisite for detecting this vulnerability class. The proposal is well-scoped, describes the CWE accurately, and does not introduce any overfitting risk since it's a foundational mapping addition rather than a detection rule. CWE-114 is a legitimate real-world vulnerability class (dynamic library loading with attacker-controlled paths).
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family reference demonstrates how CWE mappings are structured. CWE-114 is a distinct vulnerability class not covered by existing memory safety families, justifying its addition as a new mapping.
- **[Taint Rule Gap] [MODIFY]** Add a taint rule for CWE-114 that tracks data flowing from network input sources (recv, recvfrom, read on sockets) to LoadLibrary sinks (LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW, dlopen). A standalone regex for LoadLibrary produces too many false positives on hardcoded paths; the taint rule ensures only user-controlled arguments are flagged. The source is recv()/recvfrom() and the sink is LoadLibraryA/W/ExA/ExW() or dlopen().
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52a
  Suggested pattern: `LoadLibrary[AW]?(Ex[AW])?\s*\(`
  - [KB] cwe-families/CWE-114/Process Control: Untrusted input determines which code/library is loaded — Knowledge base identifies LoadLibrary() and dlopen() with user-controlled path as the core detection signals for CWE-114, defining the appropriate sink functions for the taint rule.
  - [MEMORY] pattern :: Learned regex LoadLibrary[AW]?\s*\( for CWE-114 but standalone regex without taint context produces too many false positives on safe LoadLibrary calls with hardcoded paths [cwe-114, false-positive] — Previous overfitting review identified that a regex-only approach is insufficient; a taint rule linking network sources to LoadLibrary sinks is needed to avoid false positives.
  - [MEMORY] insight :: Vulnerability pattern: recv() reads data from socket → data flows through inter-procedural calls (52a→52b→sink) → LoadLibraryA() called with tainted string [cwe-114, taint-flow] — The specific test case demonstrates the inter-procedural taint flow from recv() source to LoadLibraryA() sink that the taint rule must capture.
  Overfitting review: MODIFY | Risk: MEDIUM | Applicability: MEDIUM
  Review reason: The taint rule concept is sound and addresses real-world CWE-114 detection properly by requiring source-to-sink tracking rather than simple pattern matching. However, the source list is too narrow—it only covers network socket sources. Real-world CWE-114 vulnerabilities can originate from environment variables, command-line arguments, file reads, registry values, web request parameters, and other untrusted inputs. The sink regex in the patch field is fine as a sink identifier but the proposal should broaden the source set.
  Suggested modification: Expand the source set beyond just recv/recvfrom to include other common untrusted input sources: getenv(), argv, fgets/fread from user-controlled files, GetEnvironmentVariable(), registry reads, CGI/web input functions. This prevents overfitting to the Juliet 'connect_socket' variant while capturing the broader CWE-114 attack surface.
  - [KB] knowledge-pack/cwe-families/cwe-families — The CWE family methodology shows that vulnerability classes should be detected based on the general pattern (untrusted input to dangerous sink), not just one specific source type. Limiting to network sockets overfits to the Juliet naming convention.
  - [MEMORY] insight :: Juliet test cases use specific source variants (connect_socket, console, file, etc.) but the underlying CWE applies regardless of source [cwe-114] — The Juliet benchmark systematically varies input sources. A taint rule should generalize across all source variants to avoid overfitting to one particular source type.
- **[Agent Capability Gap] [ACCEPT]** False negative in CWE114_Process_Control__w32_char_connect_socket_52b where a tainted string received from a network socket is passed through a multi-file call chain (52a->52b->52c->52d) and eventually used in a LoadLibrary call. The scanner fails to track taint propagation across the intermediate helper functions in the 52b/52c/52d chain pattern, missing the process control vulnerability where attacker-controlled data determines which library is loaded.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  - [KB] Juliet Test Suite/CWE-114 Process Control/Multi-file taint propagation pattern 52a-52b-52c-52d — The 52-series test cases split taint propagation across four files (a, b, c, d). The scanner must follow the tainted value from the socket recv in 52a through function calls in 52b and 52c to the LoadLibrary sink in 52d. Failure to track across these boundaries causes the false negative.
  Overfitting review: ACCEPT | Risk: LOW | Applicability: HIGH
  Review reason: This proposal addresses a genuine and general-purpose capability gap: inter-procedural and cross-file taint propagation. The inability to track taint through function call chains (52a→52b→52c→52d) is a fundamental limitation that affects detection of many CWE classes, not just CWE-114. Improving this capability has broad real-world applicability since real codebases frequently pass data through multiple function layers before reaching a dangerous sink.
  - [MEMORY] failure :: Function not found in the analysis graph, indicating incomplete graph construction or missing function extraction for multi-file test cases [cwe-121] — The fn-insights KB documents an identical class of failure where multi-file call chains prevent proper analysis. This proposal generalizes the fix to CWE-114 cases with deep call chains, addressing a systemic gap rather than a test-case-specific issue.
- **[Taint Rule Gap] [MODIFY]** Add inter-procedural taint tracking rule for the 52-series call chain pattern where data flows through intermediate forwarding functions (badSink in 52b calls 52c's badSink, which calls 52d's badSink containing the LoadLibrary call). The taint from network socket input (recv) must be preserved across each function boundary to detect CWE-114 Process Control vulnerabilities.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_52b
  - [MEMORY] pattern :: Multi-file taint forwarding patterns (52a->52b->52c->52d) frequently cause false negatives because the scanner loses track of tainted data when it passes through intermediate functions that simply forward parameters without modification. [cwe-114, taint-propagation, inter-procedural] — The 52-series pattern is a known challenge for static analysis where taint must flow through multiple function call boundaries across separate files. Adding explicit taint forwarding rules for these intermediate functions resolves the false negative.
  Overfitting review: MODIFY | Risk: HIGH | Applicability: MEDIUM
  Review reason: The core idea of preserving taint across inter-procedural boundaries is sound and necessary for real-world vulnerability detection. However, the proposal is overly specific to the Juliet '52-series' naming convention (52b->52c->52d). Real-world code does not follow this pattern. The rule should be generalized to track taint through arbitrary call chains of any depth, not just the specific 52b/52c/52d forwarding pattern.
  Suggested modification: Generalize the taint tracking rule to support arbitrary inter-procedural call chain depths from network input sources (recv, recvfrom, read on sockets) to dangerous library-loading sinks (LoadLibrary, LoadLibraryA, LoadLibraryW, dlopen). Remove any reference to '52-series' or specific function naming conventions. The rule should be: any tainted data from a network source that flows through N function boundaries to a process control sink should be flagged.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 Process Control is a real vulnerability class. The taint propagation concept is valid, but the rule must generalize beyond Juliet-specific call chain naming to be useful in real-world detection.
  - [MEMORY] failure :: Agent capability gap where functions are not found in analysis graph due to incomplete graph construction [cwe-121] — The fn-insights memory shows that incomplete inter-procedural analysis leads to missed detections. This supports the need for robust inter-procedural taint tracking, but also warns against tying it to specific function naming patterns.
- **[Pattern Gap] [MODIFY]** Add detection pattern for CWE-114 (Process Control) in test case CWE114_Process_Control__w32_char_connect_socket_53a. The code likely reads a library name from a network socket and passes it through a chain of functions (53a->53b->53c->53d) before loading it via LoadLibrary, allowing an attacker to control which library is loaded into the process.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [MEMORY] pattern :: CWE-114 Process Control is a known repeated pattern gap where taint from network sources flows through function call chains to dangerous library loading sinks like LoadLibrary/LoadLibraryA [cwe-114, process-control, pattern-gap] — Memory confirms this is a known, repeated pattern gap for CWE-114 detection involving network socket sources and LoadLibrary sinks
  - [KB] CWE Database/CWE-114 Process Control/CWE-114: Process Control — CWE-114 occurs when code loads a library or executes a process based on externally-controlled input (e.g., data from a connect socket), allowing attackers to influence which code is loaded into the process
  Overfitting review: MODIFY | Risk: HIGH | Applicability: MEDIUM
  Review reason: The pattern of detecting network-sourced data flowing to LoadLibrary is a valid and important real-world detection. However, the proposal is anchored to the specific 53a->53b->53c->53d Juliet call chain. A generalized pattern should detect any flow from network input to library-loading functions regardless of the number or naming of intermediate functions.
  Suggested modification: Reframe the pattern as: detect any data path from a network socket source (recv, recvfrom, etc.) to a dynamic library loading sink (LoadLibrary, LoadLibraryA, LoadLibraryW, dlopen) regardless of intermediate function chain structure. Remove references to the 53a/53b/53c/53d naming convention.
  - [KB] kb source/cwe-families/cwe-families — CWE-114 is a legitimate vulnerability family. The source-to-sink pattern (network input -> LoadLibrary) is valid in general, but must not be tied to Juliet-specific test case structure.
- **[Taint Rule Gap] [REJECT]** Ensure taint propagation is tracked from recv/connect_socket source through the 53a->53b->53c->53d function call chain to the LoadLibrary/LoadLibraryA sink for CWE-114 Process Control detection.
  CWEs: [114] | From case: CWE114_Process_Control__w32_char_connect_socket_53a
  - [MEMORY] pattern :: Multi-function call chain taint propagation (53a through 53d pattern) is a common structure in Juliet test cases that scanners fail to track across function boundaries [cwe-114, taint-propagation, function-chain] — The 53-series test cases pass tainted data through a chain of four functions, and taint tracking must follow the data through all intermediate calls to detect the vulnerability at the final sink
  Overfitting review: REJECT | Risk: HIGH | Applicability: LOW
  Review reason: This proposal is functionally a duplicate of P1 and P2 combined, targeting the same vulnerability class (CWE-114) with the same source (recv/connect_socket) and sink (LoadLibrary). It is also heavily overfit to the Juliet 53-series naming convention. Adding this alongside P1 and P2 would create redundant rules with no additional detection capability. The concerns are already addressed by the modifications suggested for P1 and P2.
  - [KB] kb source/cwe-families/cwe-families — While CWE-114 is valid, this proposal adds nothing beyond what P1 and P2 already cover and is specific to Juliet naming conventions (53a->53b->53c->53d), making it purely duplicative and overfit.
  - [MEMORY] insight :: Redundant proposals targeting the same CWE and same source-sink pattern with only call chain naming differences are signs of benchmark overfitting [cwe-114] — The proposal duplicates the intent of P1 and P2 with no generalizable distinction, indicating overfitting to specific Juliet test case variants.

---

