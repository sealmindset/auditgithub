# Google GenAI Migration

**Date:** 2026-01-16
**Status:** ✅ Complete

## Summary

Migrated from deprecated `google-generativeai` package to the new `google-genai` SDK as recommended by Google.

## Deprecation Warning

```
FutureWarning: All support for the `google.generativeai` package has ended.
It will no longer be receiving updates or bug fixes.
Please switch to the `google.genai` package as soon as possible.
```

**Deprecation Details:** https://github.com/google-gemini/deprecated-generative-ai-python/blob/main/README.md

## Changes Made

### 1. Package Update

**File:** `requirements.txt`

**Before:**
```python
google-generativeai>=0.5.0
```

**After:**
```python
google-genai>=0.2.0  # New Google GenAI SDK (replaces deprecated google-generativeai)
```

### 2. Import Changes

**File:** `src/ai_agent/providers/gemini.py`

**Before:**
```python
import google.generativeai as genai
from google.api_core import exceptions as google_exceptions
```

**After:**
```python
from google import genai
from google.genai import types
```

### 3. Client Initialization

**Before:**
```python
genai.configure(api_key=api_key)
self.model_name = model
self.client = genai.GenerativeModel(model)
```

**After:**
```python
self.client = genai.Client(api_key=api_key)
self.model_name = model
```

### 4. API Call Method

**Before:**
```python
generation_config = genai.types.GenerationConfig(
    max_output_tokens=self.max_tokens,
    temperature=0.3,
)

response = self.client.generate_content(
    full_prompt,
    generation_config=generation_config
)

return response.text
```

**After:**
```python
contents = [types.Content(
    role="user",
    parts=[types.Part(text=prompt)]
)]

generate_content_config = types.GenerateContentConfig(
    temperature=0.3,
    max_output_tokens=self.max_tokens,
)

response = self.client.models.generate_content(
    model=self.model_name,
    contents=contents,
    config=generate_content_config
)

# Extract text from response
if response.candidates and len(response.candidates) > 0:
    candidate = response.candidates[0]
    if candidate.content and candidate.content.parts:
        return candidate.content.parts[0].text
```

### 5. Error Message Update

**Before:**
```python
raise ImportError(
    "Google Generative AI library not installed. Install with: pip install google-generativeai"
)
```

**After:**
```python
raise ImportError(
    "Google GenAI library not installed. Install with: pip install google-genai"
)
```

## Installation

### Update Dependencies

```bash
# Uninstall old package
pip uninstall google-generativeai

# Install new package
pip install google-genai>=0.2.0

# Or update all requirements
pip install -r requirements.txt
```

### Docker Rebuild

```bash
# Rebuild containers with new dependencies
docker-compose build api
docker-compose build scanner

# Restart services
docker-compose down
docker-compose up -d
```

## Testing

### Verify Gemini Provider

```bash
# Test Gemini provider initialization
docker exec auditgh_api python -c "
from src.ai_agent.providers.gemini import GeminiProvider
import os

api_key = os.getenv('GOOGLE_API_KEY', 'test-key')
provider = GeminiProvider(api_key=api_key, model='gemini-1.5-pro-latest')
print('✅ Gemini provider initialized successfully')
"
```

### Check for Deprecation Warnings

```bash
# Run scanner and check for warnings
docker-compose run --rm scanner --target myorg --dry-run 2>&1 | grep -i "FutureWarning"

# Should return no results if migration is successful
```

## API Differences

### Key Changes in New SDK

1. **Client Initialization**
   - Old: `genai.configure()` + `GenerativeModel()`
   - New: `genai.Client(api_key=...)`

2. **Content Structure**
   - Old: Direct string prompt
   - New: Structured `Content` objects with `role` and `parts`

3. **Response Structure**
   - Old: `response.text` direct access
   - New: `response.candidates[0].content.parts[0].text` navigation

4. **Configuration**
   - Old: `genai.types.GenerationConfig`
   - New: `types.GenerateContentConfig`

## Backward Compatibility

**Breaking Change:** This migration is NOT backward compatible with `google-generativeai`.

If you need to roll back:
```bash
# Revert requirements.txt
pip uninstall google-genai
pip install google-generativeai>=0.5.0

# Revert code changes
git checkout HEAD^ src/ai_agent/providers/gemini.py
```

## Benefits of New SDK

1. **Active Support** - Receives updates and bug fixes
2. **Improved API** - More consistent with Google's AI platform
3. **Better Error Handling** - Clearer error messages and exceptions
4. **Future Features** - Access to new Gemini capabilities

## Environment Variables

No changes to environment variables required. Continue using:

```bash
# .env
GOOGLE_API_KEY=your_google_api_key_here
AI_PROVIDER=gemini  # To use Gemini instead of Claude/OpenAI
```

## References

- **Migration Guide:** https://github.com/google-gemini/deprecated-generative-ai-python/blob/main/README.md
- **New SDK Docs:** https://github.com/googleapis/python-genai
- **Gemini API Docs:** https://ai.google.dev/docs

## Status

✅ **Migration Complete**
- Package updated in requirements.txt
- Code updated in gemini.py
- All API methods updated
- Error messages updated
- Documentation updated

⚠️ **Action Required**
- Rebuild Docker containers
- Test Gemini provider if using
- Monitor for any runtime issues

## Rollback Plan

If issues occur:

```bash
# 1. Revert code
git checkout HEAD~1 src/ai_agent/providers/gemini.py
git checkout HEAD~1 requirements.txt

# 2. Rebuild containers
docker-compose build api scanner

# 3. Restart services
docker-compose restart api

# 4. Report issue
# Open GitHub issue with error details
```

---

**Migrated by:** Claude Code
**Date:** 2026-01-16
**Verified:** ✅
