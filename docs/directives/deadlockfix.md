# Python Threading Deadlock Detection and Resolution

## Problem Description

A **deadlock** occurs when a thread attempts to acquire a lock it already holds. Python's `threading.Lock()` is **non-reentrant**, meaning if the same thread tries to acquire the lock twice without releasing it, the program hangs indefinitely.

### Symptoms

- Program hangs/freezes at a specific point with no error messages
- No CPU usage (thread is blocked waiting, not spinning)
- Ctrl+C may not respond immediately
- Log output stops at a predictable location
- Adding trace logging shows execution stops at a `with self._lock:` statement

---

## Root Cause Pattern

The deadlock occurs when:

1. **Method A** acquires a lock
2. **Method A** calls **Method B** while holding the lock
3. **Method B** also tries to acquire the same lock
4. Since `threading.Lock()` is non-reentrant, **Method B** blocks forever waiting for a lock that **Method A** will never release (because it's waiting for **Method B** to complete)

### Example of Deadlock Code

```python
import threading

class StateManager:
    def __init__(self):
        self._lock = threading.Lock()  # NON-REENTRANT - CAUSES DEADLOCK
        self.data = {}

    def save(self):
        """Save state to disk."""
        with self._lock:  # DEADLOCK: Already held by update()
            with open('state.pkl', 'wb') as f:
                pickle.dump(self.data, f)

    def update(self, key, value):
        """Update a value and save."""
        with self._lock:  # Acquires lock
            self.data[key] = value
            self.save()  # Calls save() which tries to acquire the SAME lock
            # ^^^ DEADLOCK OCCURS HERE ^^^
```

---

## Solution

Replace `threading.Lock()` with `threading.RLock()` (Reentrant Lock).

### What is RLock?

- **RLock** (Reentrant Lock) allows the **same thread** to acquire the lock multiple times
- Each `acquire()` must be matched with a `release()`
- Different threads still block each other (thread-safety preserved)
- No deadlock when the same thread needs the lock recursively

### Fixed Code

```python
import threading

class StateManager:
    def __init__(self):
        self._lock = threading.RLock()  # REENTRANT - SAFE FOR NESTED CALLS
        self.data = {}

    def save(self):
        """Save state to disk."""
        with self._lock:  # OK: Same thread can re-acquire
            with open('state.pkl', 'wb') as f:
                pickle.dump(self.data, f)

    def update(self, key, value):
        """Update a value and save."""
        with self._lock:  # Acquires lock (count=1)
            self.data[key] = value
            self.save()  # Re-acquires lock (count=2), then releases (count=1)
        # Lock fully released here (count=0)
```

---

## Detection Strategy

### Step 1: Search for Lock Usage

Find all files using `threading.Lock()`:

```bash
# Find files with threading.Lock
grep -rn "threading.Lock()" --include="*.py" .

# Find lock variable assignments
grep -rn "_lock\s*=\s*threading\.Lock" --include="*.py" .

# Find all lock acquisitions
grep -rn "with self\._lock" --include="*.py" .
```

### Step 2: Identify Nested Lock Patterns

For each class with a lock, check if any method:
1. Acquires the lock (`with self._lock:`)
2. Calls another method of the same class
3. That other method also acquires the lock

```bash
# Find classes with multiple methods using the same lock
grep -B5 -A20 "def.*self.*:" file.py | grep -A15 "with self._lock"
```

### Step 3: Trace Execution

If you suspect a deadlock, add trace logging:

```python
def method_a(self):
    logging.info("[TRACE] method_a: Attempting to acquire lock...")
    with self._lock:
        logging.info("[TRACE] method_a: Lock acquired")
        self.method_b()
        logging.info("[TRACE] method_a: After method_b call")
    logging.info("[TRACE] method_a: Lock released")

def method_b(self):
    logging.info("[TRACE] method_b: Attempting to acquire lock...")
    with self._lock:  # If using Lock(), execution stops here
        logging.info("[TRACE] method_b: Lock acquired")
```

**Deadlock indicator**: Log shows "Attempting to acquire lock..." but never "Lock acquired" for the nested call.

---

## Implementation Steps

### 1. Search for Potential Deadlocks

```bash
# List all files with threading.Lock
grep -rln "threading.Lock()" --include="*.py" .
```

### 2. For Each File, Analyze the Pattern

Open each file and check:

- [ ] Is the lock used in multiple methods?
- [ ] Do any methods call other methods while holding the lock?
- [ ] Are those called methods also trying to acquire the lock?

### 3. Apply the Fix

Replace:
```python
self._lock = threading.Lock()
```

With:
```python
self._lock = threading.RLock()  # RLock allows reentrant locking (same thread can acquire multiple times)
```

### 4. Verify the Fix

```bash
# Run the code that was hanging
python your_script.py

# Verify execution continues past the previously stuck point
```

---

## Common Deadlock Patterns

### Pattern 1: Save-After-Modify

```python
# DEADLOCK RISK
def modify(self, data):
    with self._lock:
        self.data = data
        self.save()  # save() also uses self._lock

def save(self):
    with self._lock:
        # write to disk
```

### Pattern 2: Validation Before Action

```python
# DEADLOCK RISK
def process(self, item):
    with self._lock:
        if self.is_valid(item):  # is_valid() also uses self._lock
            self.items.append(item)

def is_valid(self, item):
    with self._lock:
        return item not in self.processed
```

### Pattern 3: State Check and Update

```python
# DEADLOCK RISK
def mark_completed(self, name):
    with self._lock:
        self.completed.add(name)
        self.persist()  # persist() also uses self._lock

def persist(self):
    with self._lock:
        # save state
```

---

## Alternative Solutions

### Option 1: Use RLock (Recommended)

Best for most cases. Simple change, preserves existing code structure.

```python
self._lock = threading.RLock()
```

### Option 2: Internal Methods Without Locking

Create internal `_method()` versions that assume the lock is already held:

```python
def save(self):
    """Public method - acquires lock."""
    with self._lock:
        self._save_internal()

def _save_internal(self):
    """Internal method - assumes lock is held."""
    with open('state.pkl', 'wb') as f:
        pickle.dump(self.data, f)

def update(self, key, value):
    with self._lock:
        self.data[key] = value
        self._save_internal()  # No lock acquisition needed
```

### Option 3: Lock-Free Design

Restructure to avoid nested locking entirely:

```python
def update(self, key, value):
    with self._lock:
        self.data[key] = value
        data_copy = self.data.copy()
    # Lock released before save
    self._save_data(data_copy)  # Operates on copy, no lock needed

def _save_data(self, data):
    with open('state.pkl', 'wb') as f:
        pickle.dump(data, f)
```

---

## Verification Checklist

After applying fixes:

- [ ] Code that was hanging now completes
- [ ] All unit tests pass
- [ ] No new deadlocks introduced
- [ ] Thread safety is preserved (different threads still block each other)
- [ ] Remove any `[TRACE]` debugging statements added during investigation

---

## Real-World Example: ResumeState Class

### Before (Deadlock)

```python
class ResumeState:
    def __init__(self):
        self._lock = threading.Lock()  # NON-REENTRANT
        self.completed_repos = set()

    def save(self):
        with self._lock:  # DEADLOCK when called from mark_completed
            state_data = {'completed_repos': self.completed_repos}
            with open(self.state_file, 'wb') as f:
                pickle.dump(state_data, f)

    def mark_completed(self, repo_name):
        with self._lock:  # Acquires lock
            self.completed_repos.add(repo_name)
            self.save()  # DEADLOCK: save() tries to acquire same lock
```

### After (Fixed)

```python
class ResumeState:
    def __init__(self):
        self._lock = threading.RLock()  # REENTRANT - allows nested acquisition
        self.completed_repos = set()

    def save(self):
        with self._lock:  # OK: RLock allows re-entry
            state_data = {'completed_repos': self.completed_repos}
            with open(self.state_file, 'wb') as f:
                pickle.dump(state_data, f)

    def mark_completed(self, repo_name):
        with self._lock:  # Acquires lock
            self.completed_repos.add(repo_name)
            self.save()  # Re-acquires same lock (allowed with RLock)
```

---

## Quick Reference

| Lock Type | Reentrant | Use Case |
|-----------|-----------|----------|
| `threading.Lock()` | No | Simple mutual exclusion, no nested calls |
| `threading.RLock()` | Yes | Methods that call other methods using same lock |
| `threading.Semaphore()` | N/A | Limiting concurrent access to N threads |

### When to Use RLock

- Class has multiple methods that acquire the same lock
- Methods may call each other
- You want to maintain encapsulation (each method handles its own locking)

### When Lock() is Sufficient

- Only one method uses the lock
- No method calls another method while holding the lock
- Simple critical section protection

---

## Debugging Commands

```bash
# Find potential deadlock patterns
grep -rn "with self._lock" --include="*.py" . | \
  awk -F: '{print $1}' | sort | uniq -c | sort -rn

# Files with multiple lock usages are candidates for deadlock

# Check if a file uses Lock vs RLock
grep -n "threading\.\(R\)\?Lock" filename.py

# Find all method calls within locked sections
grep -A30 "with self._lock:" filename.py | grep "self\."
```

---

## Notes

- `RLock` has slightly more overhead than `Lock`, but it's negligible in most applications
- If performance is critical and you need `Lock`, use the "internal methods" pattern
- Always document when a method assumes the lock is already held
- Consider using `contextlib.contextmanager` for complex locking scenarios
