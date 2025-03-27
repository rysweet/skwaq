# Using CodeQL to Find Variant Vulnerabilities

By Benjamin Rodes, Microsoft

## Process Overview

We use a systematic approach to identify variant vulnerabilities with CodeQL:

1. Start with an initial vulnerability description
2. Determine search patterns
3. Develop and refine queries
4. Iterate until results are manageable

## Initial Information Gathering

For effective analysis, we need:

- **Description** of the problem/vulnerability
- **Bad code examples** showing vulnerable patterns
- **Good code examples** demonstrating proper remediation

## Pattern Identification

We determine what patterns to search for, generally falling into two categories:

### Path-Based Patterns

For path-based vulnerabilities, we identify:

- **Sources**: Where user input enters the system
- **Sinks**: Where user input could trigger vulnerabilities
- **Barriers**: Code that sanitizes user input before it reaches sinks

Additionally, we consider:

- Whether to use **simple dataflow** (values without modification) or **taint flow** (tracking through modifications like string concatenation)
- Any **unusual relationships** that might be missed by typical flow analysis

### Structural Patterns

These focus on:
- How variables are used
- Where variables end up
- Types involved
- Input validation patterns

## Query Development Process

1. Collaborate with vulnerability experts to understand critical aspects
2. Develop an initial generic query that may have false positives
3. Validate we're on the right track with preliminary results
4. Refine the analysis to reduce false positives
5. Consider pattern generalization or specialization

## Success Criteria

- **Primary goal**: Results refined to a reasonable volume for human review
- **Extended goal**: Further refinement to virtually eliminate false positives for continuous use (may not always be possible)