# Pydantic V2 Deprecation Warnings Resolution

## Problem

The API logs show deprecation warnings from Pydantic V2:

```
UserWarning: Valid config keys have changed in V2:
* 'orm_mode' has been renamed to 'from_attributes'
```

This occurs because the codebase uses Pydantic V1 syntax (`orm_mode = True` in a nested `Config` class) which is deprecated in Pydantic V2.

---

## Objective

Find and update all Pydantic models in the codebase that use the deprecated V1 config syntax and convert them to Pydantic V2 syntax.

---

## Migration Pattern

### Before (Pydantic V1 - Deprecated)

```python
from pydantic import BaseModel

class MyModel(BaseModel):
    id: str
    name: str

    class Config:
        orm_mode = True
```

### After (Pydantic V2 - Current)

```python
from pydantic import BaseModel

class MyModel(BaseModel):
    id: str
    name: str

    model_config = {"from_attributes": True}
```

---

## Search Pattern

Search for all occurrences of the deprecated pattern:

```bash
# Find files with orm_mode
grep -rn "orm_mode" --include="*.py" src/

# Find files with class Config inside Pydantic models
grep -rn "class Config:" --include="*.py" src/
```

---

## Files to Check

Primary locations where Pydantic models are typically defined:

| File Pattern | Description |
|--------------|-------------|
| `src/api/routers/*.py` | API route handlers with response models |
| `src/api/models.py` | SQLAlchemy + Pydantic hybrid models |
| `src/api/schemas.py` | Pydantic schemas (if exists) |
| `src/**/*_schema.py` | Any schema files |
| `src/**/*_model.py` | Any model files |

---

## Implementation Steps

1. **Search** for all files containing `orm_mode`:
   ```bash
   grep -rln "orm_mode" --include="*.py" .
   ```

2. **For each file**, find the pattern:
   ```python
   class Config:
       orm_mode = True
   ```

3. **Replace with**:
   ```python
   model_config = {"from_attributes": True}
   ```

4. **Additional V1 to V2 migrations** (if found):

   | V1 Config Key | V2 Equivalent |
   |---------------|---------------|
   | `orm_mode = True` | `from_attributes = True` |
   | `allow_mutation = False` | `frozen = True` |
   | `use_enum_values = True` | `use_enum_values = True` |
   | `validate_assignment = True` | `validate_assignment = True` |
   | `extra = "forbid"` | `extra = "forbid"` |
   | `schema_extra` | `json_schema_extra` |

5. **Verify** no warnings after restart:
   ```bash
   docker-compose restart api
   docker-compose logs api --tail 20 | grep -i "warning"
   ```

---

## Example Conversions

### Simple Model

```python
# Before
class UserResponse(BaseModel):
    id: str
    name: str
    email: str

    class Config:
        orm_mode = True

# After
class UserResponse(BaseModel):
    id: str
    name: str
    email: str

    model_config = {"from_attributes": True}
```

### Model with Multiple Config Options

```python
# Before
class StrictModel(BaseModel):
    value: int

    class Config:
        orm_mode = True
        extra = "forbid"
        validate_assignment = True

# After
class StrictModel(BaseModel):
    value: int

    model_config = {
        "from_attributes": True,
        "extra": "forbid",
        "validate_assignment": True
    }
```

### Model with schema_extra

```python
# Before
class DocumentedModel(BaseModel):
    field: str

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {"field": "value"}
        }

# After
class DocumentedModel(BaseModel):
    field: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {"field": "value"}
        }
    }
```

---

## Verification

After making changes, verify the warnings are resolved:

```bash
# Restart API
docker-compose restart api

# Check for warnings (should return empty)
docker-compose logs api 2>&1 | grep -i "orm_mode"

# Test API is still functional
curl http://localhost:8000/health
```

---

## Notes

- The `model_config` attribute is a class-level dict, not a nested class
- Both syntaxes work in Pydantic V2, but V1 syntax shows deprecation warnings
- No functional change occurs - both syntaxes produce identical behavior
- This is a cosmetic/warning fix, not a breaking change

---

## Automated Fix Script

For bulk fixes, use this sed command (test on a single file first):

```bash
# Preview changes (dry run)
grep -l "orm_mode = True" src/**/*.py | while read f; do
    echo "Would update: $f"
done

# Apply fix (creates backup .bak files)
# WARNING: Review changes before committing
find src -name "*.py" -exec sed -i.bak \
    -e '/class Config:/,/orm_mode = True/{
        s/class Config:/model_config = {"from_attributes": True}  # REVIEW/
        /orm_mode = True/d
    }' {} \;
```

**Note**: The automated script may not handle all edge cases. Manual review is recommended.
