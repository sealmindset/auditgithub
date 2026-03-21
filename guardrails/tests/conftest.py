"""Configure import paths for guardrails tests.

We import ai_safety modules directly to avoid triggering the full
services.__init__ chain (which requires psycopg2/database).
"""
import sys
import os
import importlib

# Add src to path
SRC_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'src')
sys.path.insert(0, SRC_DIR)

# Pre-load ai_safety as a standalone package to prevent services/__init__.py
# from being triggered when we import services.ai_safety.*
AI_SAFETY_DIR = os.path.join(SRC_DIR, 'services', 'ai_safety')
if os.path.isdir(AI_SAFETY_DIR):
    # Register services and services.ai_safety as namespace packages
    import types
    if 'services' not in sys.modules:
        services_mod = types.ModuleType('services')
        services_mod.__path__ = [os.path.join(SRC_DIR, 'services')]
        services_mod.__package__ = 'services'
        sys.modules['services'] = services_mod

    if 'services.ai_safety' not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            'services.ai_safety',
            os.path.join(AI_SAFETY_DIR, '__init__.py'),
            submodule_search_locations=[AI_SAFETY_DIR]
        )
        ai_safety_mod = importlib.util.module_from_spec(spec)
        sys.modules['services.ai_safety'] = ai_safety_mod
        sys.modules['services'].ai_safety = ai_safety_mod
        spec.loader.exec_module(ai_safety_mod)
