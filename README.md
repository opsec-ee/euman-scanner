# euman-scanner
Static analysis tool for C and Python that maps findings to CVE/CWE identifiers and NIST 800-53 controls.


What it does:

Analyzes C code for memory safety issues (use-after-free, buffer overflow, null dereference, integer overflow)
Analyzes Python for injection, deserialization, and cryptography weaknesses
Detects safe idioms to reduce false positives
Generates remediation prompts in ExcLisp DSL format
Includes gate reference and NIST control mapping

Single HTML file. Runs entirely in your browser. No data is transmitted anywhere - paste your code, analyze locally, close the tab. No accounts, no tracking, no server.


this simple algorithm is where th magic lies:

( ( Z X ) (AS/.\IS) ( 0 1 ) ) - delta /.\ -- bijection

Every operation exists in one of exactly four states.Not two (success/failure). Not three (success/failure/null). Four.

```
0D(Z X 0 1)     — Zero-dimensional state space

| State | Value | Name            | Meaning                    | Action       |
|-------|-------|-----------------|-----------------------------|-------------|
| Z     | 0x00  | Null/Empty      | No question asked           | Skip/ignore |
| X     | 0x01  | Unknown         | Searching / insufficient    | FAIL CLOSED |
| 0     | 0x02  | Deny/Not-Found  | Definite negative           | Handle no   |
| 1     | 0x03  | Allow/Found     | Definite positive           | Proceed     |
```

### Critical Rule: X ALWAYS Fails Closed

X is not "maybe". X is not "retry later". X is **insufficient information to
decide**. In security contexts, X means DENY. In data contexts, X means DO NOT
USE. Never treat X as a soft failure that callers can ignore.

### State Transitions

```
Z → X    query initiated (only entry)
X → X    still searching (valid loop)
X → 0    definite negative (terminal)
X → 1    definite positive (terminal)
0, 1     terminal — no transitions out
```

---

## 2. The Bijective Contract: {{0 [ a (AS/.\IS) b ] 1}}

### Reading the Notation

```
{{0 [ input (AS/.\IS) output ] 1}}
 ^^   ^^^^^  ^^^^^^^^  ^^^^^^   ^^
 ||   |      |         |        ||
 ||   |      |         |        |+-- upper bound (boolean-complete)
 ||   |      |         |        +--- bijection boundary close
 ||   |      |         +------------ output / codomain
 ||   |      +---------------------- identity preservation operator
 ||   +----------------------------- input / domain
 |+--------------------------------- lower bound (boolean-complete)
 +---------------------------------- bijection boundary open
```

**"AS it goes in, so IS it comes out"** — the mirror `/.\` guarantees the
transformation is reversible. Every input maps to exactly one output.
No collisions. No information loss. No ambiguity.

### Operator Variants

| Operator      | Name                | Meaning                        |
|---------------|---------------------|--------------------------------|
| `(AS/.\IS)`   | Identity preserved  | Bijective — fully reversible   |
| `(AS/--\WAS)` | Identity lost       | Lossy — information destroyed  |
| `(AS/++\PLUS)`| Identity expanded   | Growing — output > input       |

### When to Use

Annotate EVERY function with its bijective contract in the docstring:

```
{{0 [ input (AS/.\IS) output ] 1}}    — 1:1 mapping, reversible
{{0 [ input (AS/--\WAS) output ] 1}}  — many:1, hash/compress/summarize
{{0 [ input (AS/++\PLUS) output ] 1}} — 1:many, expand/generate/branch
```

This tells the reader (and the next LLM) exactly what the function does to
information. No guessing. No reading the implementation. The contract IS the spec.

---

## 3. GateResult: The Universal Return Type

NEVER return bare values. NEVER return boolean success/failure.
NEVER return null to indicate "not found". Wrap everything in a GateResult
that carries the 0D state.

### Pattern (pseudocode — adapt to your language)

```
GateResult<T> {
    state: State(Z | X | 0 | 1)
    value: T?          — only valid when state == 1
    reason: String?    — why state is Z/X/0 (audit trail)
}

Constructors:
    GateResult.allow(value)           → state=1, value=value
    GateResult.deny(reason)           → state=0, reason=reason
    GateResult.unknown(reason?)       → state=X, reason="fail closed"
    GateResult.null()                 → state=Z
```

### Language Implementations

**C (Euman style):**
```c
typedef struct {
    ee_state_t state;     /* 0D(Z X 0 1) */
    uint64_t   value;     /* valid iff state == EE_STATE_1 */
    const char *reason;   /* audit: why Z/X/0 */
} ee_gate_result_t;
```

**Python:**
```python
@dataclass(frozen=True, slots=True)
class GateResult(Generic[T]):
    state: State
    value: Optional[T] = None
    reason: Optional[str] = None
```

**Rust:**
```rust
pub enum GateResult<T> {
    Z,                          // null — no question
    X(Option<String>),          // unknown — fail closed
    Deny(String),               // 0 — definite no
    Allow(T),                   // 1 — definite yes
}
```

**TypeScript:**
```typescript
type GateResult<T> =
    | { state: 'Z' }
    | { state: 'X'; reason?: string }
    | { state: '0'; reason: string }
    | { state: '1'; value: T };
```

**Go:**
```go
type GateResult[T any] struct {
    State  uint8   // 0=Z, 1=X, 2=Deny, 3=Allow
    Value  T
    Reason string
}
```

---
