# Application Security CF/INT - Quiz Preparation Guide
### Estimated Study Time: 3-4 Hours

---

# PART 1: CONCEPT REVIEW (~60 min)
*Read through each section, then test yourself with the questions in Part 2*

---

## Module 1: C Programming Review

### 1A. Why C Matters for Security
- Every major OS kernel (Linux, Windows, macOS) is written in C
- "Safe" languages rely on C underneath: CPython, Ruby MRI, PHP Zend Engine, OpenSSL, curl, libpng, ImageMagick
- A C library vulnerability affects ALL languages using it (e.g., ImageTragick CVE-2016-3714)
- C is compiled, not interpreted: binary is architecture-specific AND OS-specific
- Compiler flags can add or remove security protections from the same source code

### 1B. Memory Management Responsibilities in C
- **Allocate**: decide how much and when
- **Manage pointers**: work with actual memory addresses
- **Handle buffers**: ensure data fits within allocated space
- **Free resources**: explicitly return memory to the system
- Key vulnerability classes: buffer overflows, use-after-free, memory leaks, double-free

### 1C. The Security Mindset & Defensive Programming
Five principles:
1. **Fail Fast, Fail Safe** - stop on errors, remain secure on failure
2. **Validate Everything** - every input, return value, assumption
3. **Minimize Trust Boundaries** - validate at every boundary crossing
4. **Principle of Least Privilege** - minimal necessary permissions
5. **Defense in Depth** - multiple security layers

### 1D. Buffer Overflows
- `char buffer[10]` holds 9 chars + null terminator (`\0`)
- Writing beyond buffer overwrites: local vars, saved frame pointer, return address
- `gets()` has NO bounds checking - NEVER use it
- Safe alternative: `fgets(name, sizeof(name), stdin)` - limits to buffer size minus 1
- Always check return value of `fgets` for NULL

### 1E. C Language Danger Zones
| Dangerous | Safe Alternative | Why |
|-----------|-----------------|-----|
| `gets()` | `fgets()` | No bounds checking |
| `scanf("%s", buf)` | `fgets()` + `strtol()` | No length limit |
| `printf(user_input)` | `printf("%s", user_input)` | Format string attack |
| `atoi()` | `strtol()` with error checking | No error/overflow detection |
| `strcpy()` | `strncpy()` or `strlcpy()` | No destination size check |
| `sprintf()` | `snprintf()` | No bounds checking |

### 1F. Format String Vulnerabilities
- `printf(user_input)` is DANGEROUS
- `%x` reads values from the stack
- `%n` writes to memory
- Fix: always use `printf("%s", user_input)`

### 1G. Integer Overflow
- Fixed-size integers wrap around: `unsigned char` 200 * 2 = 400 -> wraps to 144 (400 % 256)
- Real-world: Boeing 787 (power loss after 248 days), OpenSSH (remote code execution), Android FreeType (privilege escalation)
- Prevention: check BEFORE arithmetic: `if (items > 0 && quantity > UCHAR_MAX / items)`

### 1H. Memory Layout
```
High Memory
+-------------------+
| Stack             | <- grows DOWNWARD (local vars, return addresses)
| v                 |
|                   |
| ^                 |
| Heap              | <- grows UPWARD (malloc/calloc)
+-------------------+
| BSS               | <- uninitialized global/static variables
+-------------------+
| Data              | <- initialized globals, string literals (read-only)
+-------------------+
| Text (Code)       | <- compiled instructions (read-only, executable)
+-------------------+
Low Memory
```

Key facts:
- Stack and heap grow TOWARD each other, sharing one contiguous gap
- Stack overflow moves into lower addresses -> overwrites return addresses
- Guard pages between them detect collision

### 1I. Memory Hierarchy & Security Implications

| Level | Size | Speed | Security Concern |
|-------|------|-------|------------------|
| CPU Registers | ~1 KB | ~0.3 ns | Cleared on context switch |
| L1 Cache | 32-64 KB | ~1 ns | Per-core, relatively isolated |
| L2 Cache | 256-512 KB | ~3 ns | Per-core, some sharing |
| L3 Cache | 8-32 MB | ~10 ns | **Shared between cores** (side channels!) |
| RAM | 8-64 GB | ~100 ns | Process isolation varies |
| SSD | 256GB-2TB | ~100 us | Data persists after power loss |
| HDD | 1-10 TB | ~10 ms | Easiest to recover data from |

Cache timing attacks: fast retrieval = cache hit = recently used. Attackers measure nanosecond differences to infer secrets.
Side-channel attacks: Flush+Reload, Prime+Probe, **Spectre**, **Meltdown**

### 1J. Volatile vs Non-Volatile Memory
- **Volatile** (RAM, Cache, Registers): loses data on power loss. Risks: data persistence in RAM after use, cold boot attacks
- **Non-Volatile** (HDD, SSD): data remanence (deleted files recoverable), SSD wear leveling makes secure deletion nearly impossible
- **Swap files**: when RAM fills, sensitive data (passwords!) written to disk and persists after app exits. Fix: use `char[]` and explicitly zero with `memset`/`Arrays.fill`

### 1K. Stack vs Heap

| Feature | Stack | Heap |
|---------|-------|------|
| Allocation | Automatic | Manual (malloc/free) |
| Speed | Very fast | Slower |
| Size | Limited (few MB) | Large (system memory) |
| Lifetime | Function scope | Until freed |
| Thread safety | Thread-specific | Shared |
| Growth | Downward | Upward |
| Risks | Stack overflow, return addr overwrite | Use-after-free, leaks, fragmentation |

### 1L. Dynamic Memory Functions

| Function | Purpose | Initializes? | Notes |
|----------|---------|-------------|-------|
| `malloc(size)` | Allocate bytes | NO (security risk!) | Always check for NULL |
| `calloc(count, size)` | Allocate + zero | YES | Slightly slower |
| `realloc(ptr, new_size)` | Resize | No safety checks | May move allocation |
| `free(ptr)` | Release memory | N/A | Set ptr to NULL after! |

Pattern: **allocate -> use -> free -> set to NULL**

Double-free = undefined behavior (usually crash). Wild pointer = uninitialized pointer to unpredictable address.

### 1M. Four Major Vulnerability Classes
1. **Buffer Overflow**: writing past allocated boundaries -> code execution
2. **Integer Overflow**: wrap-around -> undersized allocation -> buffer overflow
3. **Use-After-Free**: accessing freed memory that may be reallocated -> attacker controls contents
4. **Format String**: `printf(user_input)` -> `%x` reads stack, `%n` writes memory

Microsoft: ~70% of all security bugs are memory safety issues

### 1N. C Compilation Pipeline (5 stages)

| Stage | Command | Output | Key Facts |
|-------|---------|--------|-----------|
| 1. Preprocessing | `gcc -E` | `.i` | Expands macros, includes headers, removes comments |
| 2. Compilation | `gcc -S` | `.s` | C -> assembly, type checking, optimizations |
| 3. Assembly | `gcc -c` | `.o` | Assembly -> machine code, unresolved references |
| 4. Linking | `gcc` | executable | Resolves references, static vs dynamic linking |
| 5. Loading | (runtime) | in memory | OS sets up memory layout, resolves dynamic libs |

- Macro pitfall: `#define SQR(x) x*x` -> `SQR(1+2)` = `1+2*1+2` = 5, not 9. Fix: `#define SQR(x) ((x)*(x))`
- Static linking: self-contained but no library updates without recompile
- Dynamic linking: smaller binary, shared library updates, but shared vulnerabilities

Binary inspection tools: `file`, `objdump`, `nm`, `strings`, `readelf`, `ldd`

---

## Module 2: Code Review & Fuzzing

### 2A. Version Control & Git
- Git: distributed VCS by Linus Torvalds (2005). Every clone has full history.
- Snapshots, not diffs. SHA hashing makes history tamper-evident.
- **Four-eyes principle**: two people must approve an action. Used in finance, nuclear, code review. Part of ISO 27001 and SOX.
- Commits: snapshot + hash + author + timestamp + message + parent pointer. Hash chain = tamper-evident.
- Staging area (index): files must be `git add`ed before committing.

### 2B. Platform Security (GitHub/GitLab)
Authentication methods:
- **SSH Keys**: asymmetric crypto, more secure than passwords
- **Personal Access Tokens (PATs)**: scoped, revocable, granular permissions, can expire
- **2FA**: TOTP, hardware keys, SMS (least secure)

Branch protection rules:
- Required reviews (minimum reviewers)
- Status checks must pass (CI tests, security scans)
- No force push (prevents hiding malicious changes)
- Signed commits required

Verified/Signed commits: GPG/SSH signing proves identity, prevents impersonation.

### 2C. CI/CD Pipeline
- **CI**: On every commit -> fetch, build, test (unit, integration, smoke). Rapid feedback.
- **CD**: Passing CI -> auto-deploy. Safeguards: blue-green, canary, auto-rollback, feature flags.

Pipeline stages: Commit & Build -> Automated Testing -> Staging Deployment -> Production Deployment

### 2D. DevSecOps - Security in CI/CD ("Shift Left")

| Tool | Type | What It Does | When |
|------|------|-------------|------|
| **SAST** | Static | Scan source code for vulnerabilities | Build time |
| **SCA** | Dependency | Check packages for known CVEs | Build time |
| **Secret Detection** | Static | Find leaked keys/passwords in commits | Build time |
| **DAST** | Dynamic | Simulate attacks on running app | Staging |
| **IAST** | Hybrid | Instrument running app during tests | Testing |
| **IaC Scanning** | Static | Check Terraform/CloudFormation for misconfigs | Build time |

Historical context:
- **Morris Worm (1988)**: first widespread internet worm, patches via floppy disk, took weeks
- **Heartbleed (2014)**: OpenSSL buffer overflow, 66% of servers affected, patched in 24-48 hours via CI/CD

### 2E. Unit Testing
- Testing individual components in isolation
- Fixing bugs in development is **10-100x cheaper** than in production
- **AAA Pattern**: Arrange (setup) -> Act (execute) -> Assert (verify)
- **Test doubles**: dummy, stub, mock, fake, spy

Test categories:
- **Happy path**: normal expected usage
- **Boundary**: min/max values, empty strings, zero
- **Error cases**: null, out-of-range, malformed data
- **Security tests**: injection attempts, buffer overflow inputs, format strings

Failure pattern -> Vulnerability mapping:
- Crash on long input -> buffer overflow
- Incorrect on special chars -> injection vulnerability
- Wrong on negative numbers -> integer underflow
- Timeout on specific input -> DoS vulnerability

### 2F. Integration Testing
- Tests interactions BETWEEN components. Vulnerabilities emerge at boundaries even when units pass individually.

Security concerns at boundaries:
- **Hidden assumptions**: teams assume different modules handle security -> auth bypasses
- **Data handling inconsistencies**: encoding differences (UTF-8 vs ASCII) -> SQL injection, XSS
- **Memory management errors**: use-after-free, double-free when ownership unclear

Real-world integration failures (KNOW THESE):

| Incident | Year | What Happened | Root Cause |
|----------|------|--------------|------------|
| **CrowdStrike** | 2024 | Millions of Windows BSOD | Missing staged deployment, kernel validation |
| **Knight Capital** | 2012 | $440M loss in 45 min | Incomplete deployment (7/8 servers), legacy flag conflict |
| **Jeep Cherokee** | 2015 | Remote car control | Entertainment system bridged to CAN bus, no security boundary |
| **NASA Mars Orbiter** | 1999 | $125M lost | Pound-seconds vs newton-seconds, no unit conversion at interface |
| **Heartbleed** | 2014 | Buffer overflow in OpenSSL | Apps inherited vulnerability without additional validation |
| **Equifax** | 2017 | 147M records stolen | Apache Struts integrated without security testing |
| **Target** | 2013 | 40M credit cards stolen | HVAC shared network with payment processing |

Integration testing strategies:
1. **Big Bang**: all at once (hard to isolate faults)
2. **Top-Down**: high-level first, stubs for lower (security layers tested late)
3. **Bottom-Up**: lowest first, drivers for higher (security validated early)
4. **Hybrid/Sandwich**: both directions, meet in middle (best for security-critical)

### 2G. Fuzzing Techniques
- Dynamic testing with random/malformed inputs to find crashes
- **Oracle**: mechanism that determines if software failed (typically: did it crash?)
- Coined by **Prof. Barton Miller** (Wisconsin, 1989). 25-33% of Unix utilities crashed on random input.

Input generation:
- **Generation-based**: create from scratch using grammar/model of expected format
- **Mutation-based**: modify valid seed files (bit flips, duplications)

Input awareness:
- **Dumb/Unstructured**: raw bytes, most inputs rejected at parsing
- **Smart/Structured**: uses format knowledge, reaches deeper code paths

Program visibility:
- **Black-box**: no internal knowledge, fast but shallow
- **Gray-box**: lightweight instrumentation, coverage-guided (**state-of-the-art**: AFL, libFuzzer)
- **White-box**: full symbolic execution, very thorough but extremely slow (Microsoft SAGE)

**Path explosion**: 10 if-statements = 2^10 = 1,024 paths. Exponential growth.

Fuzzing workflow: Select Target -> Write Harness -> Provide Seeds -> Execute Fuzzer -> Triage Crashes -> Minimize and Fix

Key tools:
- **AFL/AFL++**: genetic algorithm evolving test cases. Found bugs in OpenSSL, PHP, Firefox.
- **libFuzzer**: in-process, LLVM/Clang integrated, very fast for library functions.

### 2H. Static vs Dynamic Analysis

| Aspect | Static Analysis | Dynamic Analysis |
|--------|----------------|-----------------|
| Execution | Does NOT execute code | Executes code |
| Box type | White-box | Typically black-box |
| Coverage | All paths (including error handlers) | Only executed paths |
| False positives | More (alert fatigue) | Fewer (proves exploitability) |
| Environment | No test env needed | Requires running app |
| Catches | Code patterns, known vuln types | Runtime behavior, config issues |
| Misses | Runtime behavior, timing attacks | Dormant/unexecuted code paths |

Static methods: linting, taint analysis, control flow analysis, symbolic execution, manual review
Dynamic methods: fuzzing, pen testing, DAST scanners (OWASP ZAP, Burp Suite), runtime instrumentation (ASan, Valgrind), load/stress testing

Command injection example:
- Vulnerable: `os.system("ping -c 4 " + user_input)`
- Attack input: `8.8.8.8; whoami` -> executes arbitrary commands

### 2I. Advanced Testing
**Symbolic execution**: treats inputs as symbolic variables, explores ALL paths, uses SMT solver
- Example: `y = x+3; if (y==13) abort();` -> solver finds x=10. Random fuzzer: 1 in 2^32 chance.
- Limitation: path explosion

**Concolic testing** (Concrete + Symbolic / "dynamic symbolic execution"):
- Runs with concrete inputs while simultaneously tracking symbolic constraints
- Pioneered by **DART** and **CUTE** tools
- Process: run -> collect path constraints -> negate one constraint -> solve for new input -> repeat
- **Microsoft SAGE**: concolic whitebox fuzzing. Found ~1/3 of all new file-handling bugs during Windows 7 development.

**Best practice**: Layer techniques - linting (early, cheap) -> unit tests -> integration tests -> fuzzing (random exploration) -> symbolic/concolic (targeted deep) -> manual review (business logic)

---

## Module 3: Attacks & Defenses in C

### 3A. Compiler Flags for Security

Essential hardened build:
```
gcc -O2 -Wall -Wextra -Wformat -Werror \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -fPIE -pie \
    -Wl,-z,relro -Wl,-z,now \
    -Wl,-z,noexecstack \
    -fcf-protection=full \
    -fstack-clash-protection \
    -o secure_app secure_app.c
```

Where flags act in the pipeline:
- Preprocessing: `-D_FORTIFY_SOURCE=2`
- Compilation: `-fstack-protector-strong`, `-fPIE`, `-Wall`, optimization level
- Linking: `-Wl,-z,relro,-z,now`, `-pie`, `-Wl,-z,noexecstack`

Optimization levels:
- `-O0`: no optimization (debugging)
- `-O2`: recommended production (REQUIRED for FORTIFY_SOURCE)
- `-O3`: aggressive
- `-Os`: size optimization (embedded)

### 3B. Memory Sanitizers & Debugging Tools

| Tool | Catches | Overhead | Flag / Usage |
|------|---------|----------|-------------|
| **UBSan** | Integer overflow, null deref, bad shifts, bounds | Very low | `-fsanitize=undefined` |
| **ASan** | Buffer overflow, use-after-free, double-free, leaks | ~2x slowdown | `-fsanitize=address` |
| **MSan** | Uninitialized memory usage | - | `-fsanitize=memory` |
| **TSan** | Data races, race conditions | - | `-fsanitize=thread` |
| **Valgrind** | All above + uninitialized memory | **20-50x** slowdown | `valgrind --leak-check=full` |

ASan details:
- Uses **shadow memory**: 1 byte shadow per 8 bytes app memory
- Places **red zones** around allocations
- Shadow memory values: 0x00 = accessible, 0xfa = heap left red zone, 0xfb = heap right red zone, 0xfd = freed heap
- CANNOT be used simultaneously with Valgrind

Valgrind details:
- No recompilation needed (binary translation)
- Leak categories: definitely lost, indirectly lost, possibly lost, still reachable
- Unique strength: tracks uninitialized memory

**NEVER ship production with sanitizers enabled.** Use in development/CI/fuzzing only.

### 3C. NOP Sled / NOP Slide
- Exploitation technique for stack buffer overflow
- NOP = No Operation (x86 opcode `0x90`)
- Problem: attacker must jump to exact shellcode address, but stack addresses vary
- Solution: large "landing zone" of NOPs before shellcode. Any jump into zone slides to shellcode.

```
[High Memory]
Overwritten Return Address -> points into NOP sled
Saved Frame Pointer
Local Variables
NOP (0x90) x hundreds      <- landing zone
Shellcode                   <- actual payload
[Low Memory]
```

Polymorphic NOP equivalents (evade IDS):
- `xor eax, eax` (zeroes register)
- `inc ecx; dec ecx` (no net effect)
- `mov eax, eax` (move to itself)

Limitations: ASLR makes addresses unpredictable, DEP marks stack non-executable, 64-bit address space too vast

### 3D. Heap Spraying
- Fills large portions of heap with copies of attacker's payload
- Target: client-side attacks (browsers, PDF readers)
- Complements: use-after-free, type confusion, dangling pointer vulnerabilities

Three phases: Allocation (fill heap) -> Corruption (trigger vuln) -> Execution (corrupted pointer hits spray)

Why predictable: size classes, sequential layout, alignment rules, fragmentation avoidance

Advanced techniques:
- **JIT Spraying**: abuse JIT compilers to create executable pages (bypasses DEP!)
- **Heap Feng Shui**: carefully orchestrate alloc/dealloc for precise layouts

NOP Sleds vs Heap Spraying:

| | NOP Sleds | Heap Spraying |
|-|-----------|---------------|
| Target memory | Stack | Heap |
| Exploits | Buffer overflows | UAF, type confusion |
| Mechanism | Sequential execution | Statistical probability |
| Size | 100s-1000s bytes | 10s-100s MB |
| Era | 1990s-2000s | 2005-2015 |

### 3E. Stack Canaries
- Random value placed between local variables and saved return address
- Prologue: place canary. Epilogue: check canary before return.
- Mismatch -> `__stack_chk_fail()` -> program aborts
- Turns remote code execution into denial of service

Canary types:
- **Terminator**: includes NULL (0x00), LF (0x0a), CR (0x0d), EOF (0xff). Stops `strcpy` at NULL byte.
- **Randomized**: random value from `/dev/urandom` at startup. Unknown to attacker.

Bypassing canaries:
1. **Info leak** (format string bug to read canary value)
2. **Brute force** (32-bit: 24 bits entropy = 16.7M values, ~47 hours at 100/sec)
3. **Non-overwriting attacks** (overwrite different control data)
4. **Heap-based exploits** (skip the stack entirely)

Flags: `-fstack-protector-strong` (recommended). Performance: <1% overhead.

### 3F. ASLR (Address Space Layout Randomization)
- Randomizes: executable base (if PIE), shared libraries, stack, heap, mmap files
- 32-bit: ~8-16 bits entropy (256-65K possibilities)
- 64-bit: ~28-32+ bits entropy (hundreds of millions)

Bypassing ASLR:
1. **Information leaks**: read a pointer, calculate base addresses. One leaked address often enough.
2. **Brute force** (32-bit only): ~5.5 minutes at 100/sec. 64-bit: completely impractical.
3. **Data-only attacks**: ASLR doesn't prevent data corruption (e.g., overwriting `is_admin` flag)

PIE (Position Independent Executable): required for ASLR to randomize main executable. `-fPIE -pie`. Check: `readelf -h binary | grep Type` (DYN = PIE).

### 3G. DEP / NX Bit (Data Execution Prevention)
- Hardware-supported: marks memory regions non-executable
- Stack/heap: `rw-` (read/write, NO execute). Code (.text): `r-x` (read/execute).
- Classic shellcode injection = DEFEATED
- Forces attackers to **code reuse** attacks (ret2libc, ROP)

What DEP does NOT stop: data-only corruption, function pointer overwrites, return-to-libc, ROP

Check: `readelf -l binary | grep GNU_STACK` (RW = good, RWE = bad)
Timeline: 2004 (AMD NX, Intel XD, Windows XP SP2, Linux 2.6.8). Performance: zero overhead.

### 3H. ROP (Return-Oriented Programming)
- Bypasses DEP using existing code "gadgets" ending in `RET`
- Attacker controls stack, chains gadget addresses
- Each gadget: small instruction sequence + `RET`
- CPU can't distinguish normal returns from ROP chains

Simple x64 example (call `system("/bin/sh")`):
```
[padding to overflow]
[addr of "pop rdi; ret" gadget]   -> loads next value into RDI (first arg register)
[addr of "/bin/sh" string]         -> the argument
[addr of system()]                 -> function to call
```

Evolution: Buffer overflows (1990s) -> DEP (2004) -> Return-to-libc (2005) -> ROP generalized (2007)

Defenses against ROP:
1. ASLR (hides gadget addresses)
2. CFI (Control-Flow Integrity - ensures valid control flow)
3. **Shadow stacks / Intel CET**: separate call stack catches mismatched returns
4. Code randomization

### 3I. Defense in Depth - Complete Layering
```
Attack hits ->
  1. FORTIFY_SOURCE catches libc function overflows
  2. Stack canary detects stack corruption
  3. ASLR+PIE randomizes addresses
  4. NX/DEP prevents code injection
  5. Full RELRO prevents GOT overwrites
  6. CFI/CET prevents ROP
```

To exploit, attacker needs: info leak (defeat ASLR) + ROP chain (defeat DEP) + canary bypass

Performance overhead of all combined: typically 3-7%

### 3J. Flag Verification Commands
- `checksec --file=binary` (shows all protections)
- `objdump -t binary | grep stack_chk` (canaries)
- `readelf -h binary | grep Type` (PIE: DYN vs EXEC)
- `readelf -l binary | grep GNU_STACK` (DEP: RW vs RWE)
- `ROPgadget --binary <file>` (find ROP gadgets)

---

# PART 2: PRACTICE QUESTIONS (~90 min)
*Answer each question, then check against the answer key in Part 3*

---

## Section A: Multiple Choice (40 questions)

**Q1.** Which function should NEVER be used in C due to lack of bounds checking?
a) `fgets()`
b) `scanf()`
c) `gets()`
d) `printf()`

**Q2.** What does `printf(user_input)` allow an attacker to do?
a) Only print text to the screen
b) Read stack values with `%x` and write memory with `%n`
c) Cause a syntax error
d) Only read from memory

**Q3.** In C's memory layout, which direction does the stack grow?
a) Upward (toward higher addresses)
b) Downward (toward lower addresses)
c) It doesn't grow; it's fixed size
d) Sideways (into the heap)

**Q4.** What is the result of `unsigned char x = 200; x = x * 2;`?
a) 400
b) 144
c) 0
d) Compiler error

**Q5.** Which function initializes allocated memory to zero?
a) `malloc()`
b) `calloc()`
c) `realloc()`
d) `free()`

**Q6.** What should you do immediately after calling `free(ptr)`?
a) Call `free(ptr)` again to confirm
b) Set `ptr = NULL`
c) Call `realloc(ptr, 0)`
d) Nothing; the system handles it

**Q7.** According to Microsoft, what percentage of security bugs are memory safety issues?
a) ~30%
b) ~50%
c) ~70%
d) ~90%

**Q8.** What is the "four-eyes principle" in code review?
a) Using four different testing tools
b) Requiring two people to approve an action
c) Reviewing code four times before merge
d) Having four levels of access control

**Q9.** Which VCS architecture does Git use?
a) Centralized
b) Distributed
c) Client-server
d) Peer-to-peer

**Q10.** What does SAST stand for?
a) Static Application Security Testing
b) System Automated Security Testing
c) Source Analysis and Security Testing
d) Static Automated Scanning Tool

**Q11.** In the CI/CD context, what does "shift left" mean?
a) Move security to the end of the pipeline
b) Integrate security earlier in the development lifecycle
c) Shift responsibility to the operations team
d) Move testing to production

**Q12.** Who coined the term "fuzzing" and when?
a) Linus Torvalds, 2005
b) Prof. Barton Miller, 1989
c) Ken Thompson, 1983
d) Alan Turing, 1950

**Q13.** What percentage of Unix utilities crashed on random input in Miller's original fuzzing study?
a) 5-10%
b) 15-20%
c) 25-33%
d) 50-60%

**Q14.** What is the current state-of-the-art in fuzzing?
a) Black-box generation-based fuzzing
b) White-box symbolic execution
c) Coverage-guided gray-box mutation fuzzing (AFL/AFL++)
d) Manual input testing

**Q15.** How many execution paths exist for a program with 10 independent if-statements?
a) 10
b) 20
c) 100
d) 1,024

**Q16.** What is an "oracle" in the context of fuzzing?
a) A database query
b) A mechanism that determines if the software failed
c) A prediction algorithm
d) A type of seed file

**Q17.** In unit testing, what does the AAA pattern stand for?
a) Authenticate, Authorize, Act
b) Arrange, Act, Assert
c) Analyze, Apply, Assess
d) Abstract, Activate, Assert

**Q18.** If a program crashes on long input during testing, what vulnerability does this likely indicate?
a) SQL injection
b) Buffer overflow
c) Cross-site scripting
d) Privilege escalation

**Q19.** What was the root cause of the NASA Mars Climate Orbiter loss ($125M)?
a) Software crash during landing
b) Cosmic ray bit flip
c) Pound-seconds vs newton-seconds unit mismatch at interface
d) Fuel calculation error

**Q20.** Which integration testing strategy validates security mechanisms earliest?
a) Big Bang
b) Top-Down
c) Bottom-Up
d) Random

**Q21.** What x86 opcode represents NOP (No Operation)?
a) 0x00
b) 0xFF
c) 0x90
d) 0xCC

**Q22.** What problem does a NOP sled solve for an attacker?
a) Making shellcode smaller
b) Bypassing firewalls
c) Address uncertainty when jumping to shellcode
d) Encrypting the payload

**Q23.** Which instruction is NOT a valid NOP equivalent for a polymorphic sled?
a) `xor eax, eax`
b) `jmp +0` (jump to itself)
c) `mov eax, eax`
d) `inc ecx; dec ecx`

**Q24.** Heap spraying primarily targets which type of application?
a) Server-side daemons
b) Client-side applications (browsers, PDF readers)
c) Kernel modules
d) Network routers

**Q25.** What is JIT spraying?
a) Speeding up the JIT compiler
b) Abusing JIT compilers to create executable pages with exploit payload
c) Spraying the CPU cache
d) A denial-of-service technique

**Q26.** Why does JIT spraying bypass DEP?
a) It disables DEP
b) JIT-created pages are legitimately marked executable
c) It runs in kernel mode
d) It uses hardware vulnerabilities

**Q27.** What value does a stack canary protect?
a) The heap metadata
b) The saved return address (between local vars and return addr)
c) Global variables
d) The instruction pointer directly

**Q28.** Which canary type includes NULL (0x00), LF (0x0a), CR (0x0d)?
a) Randomized canary
b) Terminator canary
c) XOR canary
d) Sequential canary

**Q29.** What is the most common way to bypass stack canaries?
a) Brute force
b) Information leak (e.g., format string bug to read canary value)
c) Disabling the canary at runtime
d) Using a different compiler

**Q30.** How many bits of entropy does ASLR provide on a 64-bit system?
a) 8-16 bits
b) 16-24 bits
c) 28-32+ bits
d) 64 bits

**Q31.** What does PIE stand for and why is it needed?
a) Program Instruction Encoding; for faster execution
b) Position Independent Executable; required for ASLR to randomize main executable
c) Protected Instruction Environment; for DEP
d) Parallel Instruction Execution; for multi-threading

**Q32.** What does DEP/NX bit do?
a) Encrypts memory regions
b) Marks memory regions as non-executable (stack/heap can't execute code)
c) Randomizes memory addresses
d) Detects buffer overflows

**Q33.** Which attack technique was developed specifically to bypass DEP?
a) NOP sleds
b) Heap spraying
c) Return-Oriented Programming (ROP)
d) Format string attacks

**Q34.** In a ROP chain, what do all gadgets end with?
a) `NOP` instruction
b) `RET` instruction
c) `JMP` instruction
d) `CALL` instruction

**Q35.** What compiler flag enables FORTIFY_SOURCE level 2?
a) `-fstack-protector-strong`
b) `-D_FORTIFY_SOURCE=2`
c) `-fPIE`
d) `-Wl,-z,relro`

**Q36.** What optimization level is REQUIRED for FORTIFY_SOURCE to work?
a) `-O0`
b) `-O1` or higher
c) `-O2` or higher
d) `-O3` only

**Q37.** What does Full RELRO (`-Wl,-z,relro,-z,now`) prevent?
a) Stack overflows
b) GOT (Global Offset Table) overwrite attacks
c) Format string attacks
d) Integer overflows

**Q38.** What is the typical combined performance overhead of all security hardening flags?
a) 0-1%
b) 3-7%
c) 15-25%
d) 50%+

**Q39.** What is ASan's approximate runtime overhead?
a) Negligible
b) ~2x slowdown
c) ~10x slowdown
d) ~20-50x slowdown

**Q40.** What is Valgrind's approximate runtime overhead?
a) Negligible
b) ~2x slowdown
c) ~10x slowdown
d) ~20-50x slowdown

---

## Section B: Short Answer (15 questions)

**Q41.** Explain why `malloc()` not initializing memory is a security risk. What is the safe alternative?

**Q42.** What is the difference between static linking and dynamic linking? Give one security advantage and one security disadvantage of each.

**Q43.** Describe the macro pitfall with `#define SQR(x) x*x` and how to fix it.

**Q44.** What is concolic testing? Name the tool Microsoft developed using this technique and what it found.

**Q45.** Explain the difference between generation-based and mutation-based fuzzing. When would you prefer each?

**Q46.** Why can ASan and Valgrind NOT be used simultaneously?

**Q47.** How does ASan's shadow memory work? What do the values 0x00, 0xfa, and 0xfd represent?

**Q48.** What is the Knight Capital incident (2012) and what integration testing failure caused it?

**Q49.** Explain why the Target breach (2013) is an integration testing failure.

**Q50.** What is the difference between a terminator canary and a randomized canary? How does each prevent overflow?

**Q51.** Why is brute-forcing ASLR feasible on 32-bit but not 64-bit systems?

**Q52.** Explain how return-to-libc works and why DEP can't stop it.

**Q53.** What is Intel CET / shadow stack and how does it defend against ROP?

**Q54.** List the 6 layers of defense in depth for a hardened C binary (in order from first check to last).

**Q55.** What three things would an attacker need to successfully exploit a fully hardened binary (canaries + ASLR + DEP)?

---

## Section C: Scenario-Based Questions (10 questions)

**Q56.** You compile a program with `gcc -O0 -D_FORTIFY_SOURCE=2 program.c`. Will FORTIFY_SOURCE protections be active? Why or why not?

**Q57.** A security audit reveals that a web application's C backend uses `printf(request->body)` to log HTTP request bodies. What attack is possible and how would you fix it?

**Q58.** You run `readelf -l binary | grep GNU_STACK` and see `RWE`. What does this mean and what should you do?

**Q59.** A developer writes: `int *data = malloc(user_count * sizeof(int));` where `user_count` comes from user input. Identify at least two vulnerabilities.

**Q60.** You're testing a file parser and it crashes when given a 10,000-byte input but works fine with 100 bytes. What type of vulnerability is this likely? What tools would you use to investigate?

**Q61.** A program uses `char password[64]` on the stack. An attacker has found a format string vulnerability in the same function. Describe two things the attacker could potentially do.

**Q62.** Your team is deciding between ASan and Valgrind for testing a third-party closed-source binary. Which should you choose and why?

**Q63.** Explain why a program that passes all unit tests might still have a critical vulnerability that only integration testing would catch. Give a specific example from the course material.

**Q64.** An attacker has found a use-after-free vulnerability in a browser. They want to use heap spraying. Describe the three phases of their attack.

**Q65.** You run `checksec --file=myapp` and see: No canary, No PIE, NX enabled, No RELRO. Which attacks is this binary vulnerable to? What compilation flags would you add?

---

# PART 3: ANSWER KEY (~30 min to review)

---

## Section A Answers

| Q | Answer | Key Fact |
|---|--------|----------|
| 1 | **c) `gets()`** | Has absolutely no bounds checking; banned in C11 |
| 2 | **b) Read stack with `%x`, write memory with `%n`** | Format string vulnerability |
| 3 | **b) Downward** | Toward lower addresses; overflows overwrite return addresses |
| 4 | **b) 144** | 400 % 256 = 144 (unsigned char wraps at 256) |
| 5 | **b) `calloc()`** | malloc does NOT initialize; calloc zeros all bytes |
| 6 | **b) Set `ptr = NULL`** | Prevents dangling pointer / use-after-free |
| 7 | **c) ~70%** | Memory safety is the dominant vulnerability class |
| 8 | **b) Requiring two people to approve** | Part of ISO 27001 and SOX compliance |
| 9 | **b) Distributed** | Every clone has full history; no single point of failure |
| 10 | **a) Static Application Security Testing** | Scans source code without executing |
| 11 | **b) Integrate security earlier** | Core DevSecOps principle |
| 12 | **b) Prof. Barton Miller, 1989** | University of Wisconsin |
| 13 | **c) 25-33%** | Crashed on random input |
| 14 | **c) Coverage-guided gray-box mutation (AFL/AFL++)** | Uses instrumentation + genetic algorithm |
| 15 | **d) 1,024** | 2^10 = 1,024 paths |
| 16 | **b) Mechanism that determines if software failed** | Term from Alan Turing's computability theory |
| 17 | **b) Arrange, Act, Assert** | Standard unit test pattern |
| 18 | **b) Buffer overflow** | Crash on long input = writing past buffer bounds |
| 19 | **c) Unit mismatch at interface** | Lockheed pound-seconds vs NASA newton-seconds |
| 20 | **c) Bottom-Up** | Validates security mechanisms (lowest layers) first |
| 21 | **c) 0x90** | Standard x86 NOP opcode |
| 22 | **c) Address uncertainty** | Sled creates landing zone; any jump into it slides to shellcode |
| 23 | **b) `jmp +0`** | Creates infinite loop, NOT useful as NOP slide |
| 24 | **b) Client-side (browsers, PDF readers)** | Exploits scripting engines to fill heap |
| 25 | **b) Abusing JIT compilers for executable pages** | Creates exploit payload in legitimately executable memory |
| 26 | **b) JIT pages are legitimately marked executable** | The JIT compiler itself marks them executable |
| 27 | **b) Saved return address** | Placed between local vars and saved return addr |
| 28 | **b) Terminator canary** | NULL byte stops strcpy from overwriting past canary |
| 29 | **b) Information leak** | Format string bug reads canary; include correct value in overflow |
| 30 | **c) 28-32+ bits** | Hundreds of millions of possibilities |
| 31 | **b) Position Independent Executable; for ASLR** | Without PIE, main executable loaded at fixed address |
| 32 | **b) Marks regions non-executable** | Hardware-enforced; stack/heap can't execute code |
| 33 | **c) ROP** | Uses existing code gadgets; doesn't need to inject code |
| 34 | **b) `RET` instruction** | Chains execution through stack-controlled addresses |
| 35 | **b) `-D_FORTIFY_SOURCE=2`** | Defines macro for checked libc functions |
| 36 | **c) `-O2` or higher** | Fortify needs optimization to work |
| 37 | **b) GOT overwrite attacks** | Makes Global Offset Table read-only after relocation |
| 38 | **b) 3-7%** | Very reasonable for the protection gained |
| 39 | **b) ~2x slowdown** | Shadow memory technique |
| 40 | **d) ~20-50x slowdown** | Binary translation approach |

## Section B Answers

**Q41.** `malloc()` returns memory containing whatever data was previously stored there (leftover from other programs/functions). This can leak passwords, encryption keys, or other sensitive data. Safe alternative: use `calloc()` which initializes all bytes to zero, or manually zero with `memset()` after `malloc()`.

**Q42.** Static linking: copies library code into binary. Advantage: self-contained, no dependency on system libraries. Disadvantage: no library security updates without recompilation. Dynamic linking: references shared libraries resolved at runtime. Advantage: library patches apply to all programs automatically. Disadvantage: a vulnerable shared library affects ALL programs using it.

**Q43.** `SQR(1+2)` expands to `1+2*1+2` = 5, not 9. Operator precedence causes `*` to bind first. Fix: `#define SQR(x) ((x)*(x))` - parentheses force correct evaluation order.

**Q44.** Concolic testing = CONcrete + symbOLIC. Runs program with concrete inputs while simultaneously performing symbolic analysis. Collects path constraints, negates one to explore new paths. Microsoft **SAGE** used this technique and found approximately 1/3 of all new file-handling bugs during Windows 7 development, including an exploitable bug in ANI file parsing that blackbox fuzzing missed.

**Q45.** Generation-based: creates inputs from scratch using a grammar/model of the expected format (e.g., building valid PNG headers). Best when you know the input format and want to test deep parsing logic. Mutation-based: starts with valid seed files and applies random modifications (bit flips, byte insertion). Best when you have good sample inputs and want broad coverage quickly. Modern tools combine both.

**Q46.** Both tools instrument memory accesses but use incompatible mechanisms. ASan uses compile-time instrumentation with shadow memory; Valgrind uses binary translation at runtime. Running both simultaneously would cause conflicts and incorrect results.

**Q47.** ASan allocates 1 byte of shadow memory for every 8 bytes of application memory. Values: 0x00 = all 8 bytes accessible (normal memory), 0xfa = heap left red zone (poisoned buffer boundary), 0xfd = freed heap memory (catches use-after-free). Before every memory access, ASan checks the corresponding shadow byte.

**Q48.** Knight Capital lost $440M in 45 minutes in 2012. During a deployment, only 7 of 8 servers were updated with new code. The 8th server still had legacy code that interpreted a repurposed configuration flag differently, causing a runaway trading loop. Root cause: incomplete deployment and legacy code flag conflict - a classic integration testing failure.

**Q49.** Target's HVAC vendor systems shared the same network as payment processing. Attackers compromised the HVAC system and pivoted to the payment network, stealing 40 million credit cards. Each system (HVAC, payments) worked correctly in isolation, but the integration lacked a security boundary between them.

**Q50.** Terminator canary includes special characters (NULL 0x00, LF 0x0a, CR 0x0d, EOF 0xff) that terminate string operations - `strcpy()` stops at the NULL byte, so overflow can't write past the canary. Randomized canary uses a random value from `/dev/urandom` set at program startup - the attacker doesn't know what value to write to maintain the canary through an overflow.

**Q51.** 32-bit ASLR has only ~8-16 bits of entropy (256-65K possibilities). At 100 attempts/second, brute force takes ~5.5 minutes. 64-bit ASLR has ~28-32+ bits of entropy (hundreds of millions of possibilities), making brute force completely impractical.

**Q52.** Return-to-libc overwrites the return address to point to an existing function like `system()` in the C library, with arguments arranged on the stack so `system()` receives `/bin/sh`. Since `system()` is in the `.text` segment (legitimately marked executable), DEP can't stop it - no injected code is executed, only existing code.

**Q53.** Intel CET maintains a separate "shadow call stack" that records return addresses when functions are called. On function return, the CPU compares the return address from the normal stack with the shadow stack. ROP modifies the normal stack but can't modify the hardware-protected shadow stack, so the mismatch is detected and execution is halted.

**Q54.** 1) FORTIFY_SOURCE catches libc function overflows -> 2) Stack canary detects stack corruption -> 3) ASLR+PIE randomizes addresses -> 4) NX/DEP prevents code injection -> 5) Full RELRO prevents GOT overwrites -> 6) CFI/CET prevents ROP.

**Q55.** An attacker needs: (1) an information leak to defeat ASLR and find addresses, (2) a ROP chain to defeat DEP (can't inject code), and (3) a way to bypass the stack canary (either by leaking its value or using a non-stack exploit path).

## Section C Answers

**Q56.** No, FORTIFY_SOURCE will NOT be active. `-D_FORTIFY_SOURCE=2` requires `-O2` or higher optimization to function. At `-O0`, the compiler doesn't have enough optimization information to insert the checked function replacements. Fix: change to `-O2 -D_FORTIFY_SOURCE=2`.

**Q57.** This is a **format string vulnerability**. An attacker can craft an HTTP body containing `%x%x%x%x` to read stack values (potentially leaking sensitive data, canary values, or addresses), or use `%n` to write to memory for code execution. Fix: change to `printf("%s", request->body)` - always use an explicit format string.

**Q58.** `RWE` means the stack is marked Read-Write-**Execute**, meaning DEP/NX is NOT enabled. The stack can execute injected code (classic shellcode injection is possible). Fix: recompile with `-Wl,-z,noexecstack` or ensure the linker isn't adding executable stack permissions (check for inline assembly or nested functions that require it).

**Q59.** (1) **Integer overflow**: if `user_count` is very large, `user_count * sizeof(int)` can overflow, wrapping to a small value. `malloc()` allocates a tiny buffer, and subsequent writes overflow it. (2) **No NULL check**: `malloc()` can return NULL on failure; dereferencing NULL = crash/undefined behavior. (3) **No input validation**: `user_count` from user input could be negative (signed), zero, or astronomically large. Fix: validate range, check for overflow before multiplication, check `malloc()` return.

**Q60.** This is likely a **buffer overflow** - the program has a fixed-size buffer that's sufficient for 100 bytes but overflowed by 10,000. Tools: (1) **ASan** (`-fsanitize=address`) to get exact location and type of overflow, (2) **AFL/AFL++** to find the minimum input that triggers the crash, (3) **Valgrind** for detailed memory analysis, (4) **GDB** to examine the crash and stack state.

**Q61.** With a format string vulnerability: (1) **Read the password from the stack** using `%x` format specifiers to dump stack contents, since the password buffer is on the same stack frame. (2) **Read the stack canary** value, which enables a subsequent buffer overflow attack by writing the correct canary value. Additionally, they could use `%n` to write to memory or leak ASLR addresses.

**Q62.** **Valgrind**, because it works on any compiled binary without needing recompilation. ASan requires compiling the source code with `-fsanitize=address`, which is impossible for a closed-source binary. Valgrind uses binary translation to instrument the program at runtime. Trade-off: Valgrind has 20-50x overhead vs ASan's 2x, but it's the only option for closed-source.

**Q63.** The **door + lock analogy**: a sliding door and bolt lock each pass unit tests individually, but together they fail because a bolt lock requires a hinged door frame. Real example: **Target (2013)** - the HVAC system and payment system both worked correctly in isolation (unit tests pass), but integrating them on the same network created a vulnerability path. Another: **NASA Mars Orbiter** - Lockheed's module correctly output pound-seconds, NASA's module correctly expected newton-seconds, but the interface between them had no unit conversion.

**Q64.** (1) **Allocation phase**: Attacker uses JavaScript to allocate many large memory blocks (e.g., 100 x 1MB), each filled with NOP sled + shellcode. Blocks stored in an array to prevent garbage collection. (2) **Corruption phase**: Trigger the use-after-free vulnerability to corrupt a pointer (e.g., a vtable pointer or function pointer in the freed object). (3) **Execution phase**: When the program dereferences the corrupted pointer, it lands in the sprayed heap region. The NOP sled guides execution to the shellcode.

**Q65.** Vulnerable to: **stack buffer overflow with shellcode** (no canary to detect, NX prevents this but...), **return address overwrite** (no canary), **GOT overwrite** (no RELRO), **ROP** (no ASLR/PIE means gadget addresses are fixed and known). NX is the only protection. Add flags: `-fstack-protector-strong` (canaries), `-fPIE -pie` (ASLR for executable), `-Wl,-z,relro -Wl,-z,now` (Full RELRO), `-D_FORTIFY_SOURCE=2` (checked libc functions), `-fcf-protection=full` (CET/CFI against ROP).

---

# PART 4: RAPID-FIRE FLASHCARD REVIEW (~20 min)
*Cover the right column and test yourself*

| Term | Definition |
|------|-----------|
| Buffer overflow | Writing past allocated buffer boundaries |
| Use-after-free | Accessing memory after it has been freed |
| Double-free | Freeing the same memory pointer twice (undefined behavior) |
| Dangling pointer | Pointer to memory that has been freed or is out of scope |
| Wild pointer | Uninitialized pointer pointing to unpredictable address |
| Format string attack | `printf(user_input)` allowing `%x` reads and `%n` writes |
| Integer overflow | Fixed-size integer wrapping around its maximum value |
| NOP sled | Landing zone of NOP instructions preceding shellcode |
| Heap spraying | Filling heap with copies of payload for probabilistic exploitation |
| Stack canary | Random value between local vars and return addr; checked before return |
| ASLR | Randomizing memory layout each execution |
| PIE | Position Independent Executable; enables ASLR for main binary |
| DEP/NX | Hardware-enforced non-executable memory regions |
| ROP | Chaining existing code gadgets (ending in RET) to bypass DEP |
| FORTIFY_SOURCE | Compile-time replacement of unsafe libc functions with checked versions |
| RELRO | Making GOT read-only to prevent overwrite attacks |
| Shadow stack | Separate call stack that detects ROP by comparing return addresses |
| SAST | Static analysis of source code without execution |
| DAST | Dynamic testing of running application |
| SCA | Scanning dependencies for known CVEs |
| Fuzzing | Automated testing with random/malformed inputs |
| AFL | American Fuzzy Lop; coverage-guided gray-box fuzzer |
| Concolic testing | Concrete + symbolic execution hybrid |
| Symbolic execution | Using symbolic variables to explore all paths via constraint solving |
| Path explosion | Exponential growth of paths with branches (2^n) |
| Four-eyes principle | Two people must approve an action |
| AAA pattern | Arrange, Act, Assert (unit testing) |
| Taint analysis | Tracking untrusted input through code to sensitive operations |
| `calloc` vs `malloc` | calloc zeros memory; malloc leaves whatever was there before |
| `strtol` vs `atoi` | strtol has error detection and overflow protection; atoi has neither |
| Terminator canary | Contains NULL/LF/CR/EOF bytes that stop string functions |
| Gray-box fuzzing | Lightweight instrumentation for coverage guidance |
| Cold boot attack | Recovering RAM contents by cooling memory chips after power off |
| Data remanence | Deleted data remaining recoverable on storage media |
| Swap risk | Sensitive RAM data written to permanent storage when OS swaps |

---

# STUDY SCHEDULE SUGGESTION

| Time Block | Activity | Section |
|-----------|----------|---------|
| 0:00-1:00 | Read through Part 1 (Concept Review) | All 3 modules |
| 1:00-1:15 | Break | - |
| 1:15-2:00 | Answer Section A (Multiple Choice) + check answers | Part 2A + 3A |
| 2:00-2:45 | Answer Sections B & C (Short Answer + Scenarios) | Part 2B-C |
| 2:45-3:00 | Break | - |
| 3:00-3:30 | Review wrong answers, re-read weak areas in Part 1 | Targeted review |
| 3:30-3:50 | Rapid-fire flashcard review | Part 4 |
| 3:50-4:00 | Final pass on integration failure case studies + defense layers | 2F + 3I |
