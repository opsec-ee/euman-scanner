# euman-scanner
Static analysis tool for C and Python that maps findings to CVE/CWE identifiers and NIST 800-53 controls.


What it does:

Analyzes C code for memory safety issues (use-after-free, buffer overflow, null dereference, integer overflow)
Analyzes Python for injection, deserialization, and cryptography weaknesses
Detects safe idioms to reduce false positives
Generates remediation prompts in ExcLisp DSL format
Includes gate reference and NIST control mapping

How Claude helped:
Built iteratively across multiple sessions. Started as a basic pattern matcher, evolved into a dual-language scanner with three tabs (Analyze, ExcLisp Composer, Gate Reference). Claude designed the ExcLisp grammar {AUTH}::DOMAIN(OP)[MECH], identified safe idiom patterns for false positive reduction, and mapped 26 security gates to their corresponding CWE and NIST controls.
Security & Privacy:
Single HTML file. Runs entirely in your browser. No data is transmitted anywhere - paste your code, analyze locally, close the tab. No accounts, no tracking, no server.
