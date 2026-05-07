"""
Self-Annealing Diagram Executor

DOE (Design of Experiments) style self-correcting diagram generation that:
1. Pre-validates imports against the diagrams index
2. Automatically corrects known import errors
3. Attempts multiple retries with AI-powered fixes
4. Learns from errors and applies progressive fixes
"""

import re
import os
import subprocess
import tempfile
import base64
import logging
from typing import Optional, Dict, Tuple, List, Any

logger = logging.getLogger(__name__)

# Known import corrections - common mistakes and their fixes
KNOWN_IMPORT_CORRECTIONS = {
    # Internet is commonly placed in wrong module
    "diagrams.generic.network.Internet": "diagrams.onprem.network.Internet",
    "diagrams.network.Internet": "diagrams.onprem.network.Internet",
    "diagrams.generic.Internet": "diagrams.onprem.network.Internet",
    
    # User/Client corrections
    "diagrams.generic.user.User": "diagrams.onprem.client.User",
    "diagrams.generic.client.User": "diagrams.onprem.client.User",
    "diagrams.user.User": "diagrams.onprem.client.User",
    "diagrams.client.User": "diagrams.onprem.client.User",
    "diagrams.generic.Client": "diagrams.onprem.client.Client",
    
    # Database corrections - Sqlite doesn't exist, use generic SQL
    "diagrams.generic.database.Database": "diagrams.generic.database.SQL",
    "diagrams.database.Database": "diagrams.generic.database.SQL",
    "diagrams.onprem.database.Sqlite": "diagrams.generic.database.SQL",
    "diagrams.onprem.database.SQLite": "diagrams.generic.database.SQL",
    "diagrams.database.Sqlite": "diagrams.generic.database.SQL",
    "diagrams.database.SQLite": "diagrams.generic.database.SQL",
    
    # Firewall corrections
    "diagrams.generic.security.Firewall": "diagrams.generic.network.Firewall",
    "diagrams.security.Firewall": "diagrams.generic.network.Firewall",
    
    # Load Balancer corrections
    "diagrams.generic.network.LoadBalancer": "diagrams.onprem.network.Haproxy",
    
    # Server corrections
    "diagrams.generic.compute.Server": "diagrams.onprem.compute.Server",
    "diagrams.compute.Server": "diagrams.onprem.compute.Server",
}

# Patterns to detect import errors
IMPORT_ERROR_PATTERNS = [
    r"ImportError: cannot import name '(\w+)' from '([\w.]+)'",
    r"ModuleNotFoundError: No module named '([\w.]+)'",
    r"cannot import name '(\w+)'",
    r"No module named '([\w.]+)'",
]


def extract_imports_from_code(code: str) -> List[Tuple[str, str]]:
    """
    Extract all import statements from code.
    Returns list of (module_path, class_name) tuples.
    """
    imports = []
    
    # Match: from diagrams.xxx import Yyy, Zzz
    pattern1 = r'from\s+(diagrams[\w.]+)\s+import\s+([\w,\s]+)'
    for match in re.finditer(pattern1, code):
        module = match.group(1)
        classes = [c.strip() for c in match.group(2).split(',')]
        for cls in classes:
            if cls:
                imports.append((module, cls))
    
    return imports


def validate_imports_against_index(
    imports: List[Tuple[str, str]], 
    diagrams_index: Dict[str, str]
) -> List[Tuple[str, str, str]]:
    """
    Validate imports against the diagrams index.
    Returns list of (module, class, correct_path) for invalid imports.
    """
    issues = []
    
    for module, cls in imports:
        full_path = f"{module}.{cls}"
        
        # Check if this exact path is in known corrections
        if full_path in KNOWN_IMPORT_CORRECTIONS:
            correct_path = KNOWN_IMPORT_CORRECTIONS[full_path]
            issues.append((module, cls, correct_path))
            continue
        
        # Check if the class exists in the index
        if cls in diagrams_index:
            indexed_path = diagrams_index[cls]
            expected_module = indexed_path.rsplit('.', 1)[0]
            if module != expected_module:
                issues.append((module, cls, indexed_path))
    
    return issues


def apply_import_corrections(code: str, corrections: List[Tuple[str, str, str]]) -> str:
    """
    Apply import corrections to the code.
    """
    corrected_code = code
    
    for old_module, cls, correct_path in corrections:
        correct_module = correct_path.rsplit('.', 1)[0]
        old_import = f"from {old_module} import {cls}"
        new_import = f"from {correct_module} import {cls}"
        
        corrected_code = corrected_code.replace(old_import, new_import)
        logger.info(f"Self-annealing: Corrected import {old_import} -> {new_import}")
    
    return corrected_code


def apply_known_corrections(code: str) -> Tuple[str, List[str]]:
    """
    Apply all known import corrections to the code.
    Returns (corrected_code, list_of_changes_made).
    """
    changes = []
    corrected = code

    # Sort for deterministic order
    for wrong_path, correct_path in sorted(KNOWN_IMPORT_CORRECTIONS.items()):
        # Extract module and class from paths
        wrong_parts = wrong_path.rsplit('.', 1)
        correct_parts = correct_path.rsplit('.', 1)
        
        if len(wrong_parts) == 2 and len(correct_parts) == 2:
            wrong_module, cls = wrong_parts
            correct_module, correct_cls = correct_parts
            
            old_import = f"from {wrong_module} import {cls}"
            new_import = f"from {correct_module} import {correct_cls}"
            
            if old_import in corrected:
                corrected = corrected.replace(old_import, new_import)
                # Also replace usage of the class if name changed
                if cls != correct_cls:
                    # Replace class usage (but not in strings or comments)
                    corrected = re.sub(rf'\b{cls}\b(?=\s*\()', correct_cls, corrected)
                changes.append(f"{old_import} -> {new_import}")
    
    # Additional runtime fixes for common issues
    # Fix Sqlite -> SQL (class name change)
    if 'from diagrams.onprem.database import Sqlite' in corrected:
        corrected = corrected.replace(
            'from diagrams.onprem.database import Sqlite',
            'from diagrams.generic.database import SQL'
        )
        corrected = re.sub(r'\bSqlite\b(?=\s*\()', 'SQL', corrected)
        changes.append('Sqlite -> SQL (class does not exist)')
    
    return corrected, changes


def parse_error_for_import_issue(error: str) -> Optional[Tuple[str, str]]:
    """
    Parse an error message to extract import issue details.
    Returns (class_name, module) or None.
    """
    for pattern in IMPORT_ERROR_PATTERNS:
        match = re.search(pattern, error)
        if match:
            groups = match.groups()
            if len(groups) == 2:
                return (groups[0], groups[1])
            elif len(groups) == 1:
                return (groups[0], None)
    return None


def find_correct_import(
    class_name: str,
    diagrams_index: Dict[str, str],
    context_hint: Optional[str] = None
) -> Optional[str]:
    """
    Find the correct import path for a class name.
    Uses context hint to prefer certain providers (aws, azure, gcp, onprem).
    """
    if class_name in diagrams_index:
        return diagrams_index[class_name]

    # Try case-insensitive search (sort for deterministic order)
    for name, path in sorted(diagrams_index.items()):
        if name.lower() == class_name.lower():
            return path

    # Try partial match for common patterns (sort for deterministic order)
    partial_matches = []
    for name, path in sorted(diagrams_index.items()):
        if class_name.lower() in name.lower():
            partial_matches.append((name, path))

    if partial_matches:
        # Sort partial matches for deterministic order
        partial_matches.sort()
        # If we have a context hint, prefer matches from that provider
        if context_hint:
            for name, path in partial_matches:
                if context_hint.lower() in path.lower():
                    return path
        # Otherwise return first match (now deterministic after sorting)
        return partial_matches[0][1]

    return None


def execute_with_self_annealing(
    code: str,
    diagrams_index: Dict[str, str],
    ai_fix_callback=None,
    max_retries: int = 3,
    report_context: Optional[str] = None
) -> Tuple[Optional[str], str, List[str]]:
    """
    Execute diagram code with self-annealing error correction.
    
    Args:
        code: The Python diagram code to execute
        diagrams_index: Index of available diagram nodes
        ai_fix_callback: Optional async callback for AI-powered fixes
        max_retries: Maximum number of fix attempts
        report_context: Optional context about the project for better fixes
    
    Returns:
        (base64_image, final_code, fix_log) - Image may be None if all attempts fail
    """
    fix_log = []
    current_code = code
    
    # Step 1: Pre-validation - Apply known corrections before execution
    pre_corrections = []
    imports = extract_imports_from_code(current_code)
    issues = validate_imports_against_index(imports, diagrams_index)
    
    if issues:
        for old_module, cls, correct_path in issues:
            pre_corrections.append(f"Pre-fix: {old_module}.{cls} -> {correct_path}")
        current_code = apply_import_corrections(current_code, issues)
        fix_log.extend(pre_corrections)
        logger.info(f"Self-annealing pre-validation: Applied {len(pre_corrections)} corrections")
    
    # Step 2: Apply all known corrections
    current_code, known_changes = apply_known_corrections(current_code)
    if known_changes:
        fix_log.extend([f"Known fix: {c}" for c in known_changes])
        logger.info(f"Self-annealing: Applied {len(known_changes)} known corrections")
    
    # Step 3: Execute with retry loop
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            image_b64 = _execute_diagram_code(current_code)
            fix_log.append(f"Success on attempt {attempt + 1}")
            logger.info(f"Self-annealing: Diagram generated successfully on attempt {attempt + 1}")
            return image_b64, current_code, fix_log
        
        except Exception as e:
            last_error = str(e)
            fix_log.append(f"Attempt {attempt + 1} failed: {last_error[:100]}...")
            logger.warning(f"Self-annealing attempt {attempt + 1} failed: {e}")
            
            if attempt >= max_retries:
                break
            
            # Step 4: Try to fix the error
            fixed = False
            
            # 4a: Parse error for import issue
            import_issue = parse_error_for_import_issue(last_error)
            if import_issue:
                class_name, module = import_issue
                correct_path = find_correct_import(class_name, diagrams_index, report_context)
                
                if correct_path:
                    correct_module = correct_path.rsplit('.', 1)[0]
                    if module:
                        old_import = f"from {module} import {class_name}"
                    else:
                        # Try to find the bad import in code
                        old_import_match = re.search(
                            rf'from\s+([\w.]+)\s+import\s+(?:[\w,\s]*\b{class_name}\b)',
                            current_code
                        )
                        if old_import_match:
                            old_import = old_import_match.group(0)
                        else:
                            old_import = None
                    
                    if old_import:
                        new_import = f"from {correct_module} import {class_name}"
                        if old_import in current_code:
                            current_code = current_code.replace(old_import, new_import)
                            fix_log.append(f"Error-based fix: {old_import} -> {new_import}")
                            fixed = True
            
            # 4b: If we have an AI callback and couldn't fix it ourselves, use AI
            if not fixed and ai_fix_callback:
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    ai_fixed_code = loop.run_until_complete(
                        ai_fix_callback(current_code, last_error, diagrams_index, report_context)
                    )
                    
                    # Clean up code block if present
                    code_match = re.search(r"```python\n(.*?)```", ai_fixed_code, re.DOTALL)
                    if code_match:
                        ai_fixed_code = code_match.group(1).strip()
                    else:
                        ai_fixed_code = ai_fixed_code.replace("```python", "").replace("```", "").strip()
                    
                    current_code = ai_fixed_code
                    fix_log.append(f"AI-powered fix applied")
                    fixed = True
                except Exception as ai_error:
                    fix_log.append(f"AI fix failed: {str(ai_error)[:50]}")
                    logger.error(f"Self-annealing AI fix failed: {ai_error}")
            
            if not fixed:
                fix_log.append(f"Could not auto-fix error, retrying with current code")
    
    # All attempts failed
    logger.error(f"Self-annealing: All {max_retries + 1} attempts failed. Last error: {last_error}")
    return None, current_code, fix_log


def _execute_diagram_code(code: str) -> str:
    """
    Execute Python code to generate diagram and return base64 image.
    Internal function used by self-annealing executor.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = os.path.join(tmpdir, "diagram_script.py")
        
        with open(script_path, "w") as f:
            f.write(code)
        
        try:
            subprocess.check_output(
                ["python3", script_path],
                cwd=tmpdir,
                stderr=subprocess.STDOUT,
                timeout=30
            )
        except subprocess.CalledProcessError as e:
            raise Exception(f"Script execution failed: {e.output.decode()}")
        
        # Find PNG
        png_path = os.path.join(tmpdir, "architecture_diagram.png")
        if not os.path.exists(png_path):
            files = [f for f in os.listdir(tmpdir) if f.endswith('.png')]
            if files:
                png_path = os.path.join(tmpdir, files[0])
            else:
                raise Exception("No PNG image generated by the script")
        
        with open(png_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
