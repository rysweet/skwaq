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

