import os
import fnmatch
from typing import Dict, List, Tuple

# Files to ignore during traversal
IGNORE_PATTERNS = [
    '.git', '.idea', '.vscode', '__pycache__', 'node_modules', 
    'dist', 'build', 'coverage', '.env', '.DS_Store',
    '*.pyc', '*.pyo', '*.pyd', '*.so', '*.dll', '*.exe',
    'package-lock.json', 'yarn.lock', 'go.sum', 'Cargo.lock'
]

# Key configuration files to read content from
CONFIG_FILES = [
    'package.json', 'requirements.txt', 'Pipfile', 'pyproject.toml',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'go.mod', 'Cargo.toml', 'pom.xml', 'build.gradle',
    'Makefile', 'Rakefile', 'Gemfile',
    'tsconfig.json', 'webpack.config.js', 'next.config.js',
    '.gitlab-ci.yml', '.github/workflows/*.yml', '.github/workflows/*.yaml',
    'azure-pipelines.yml', 'bitbucket-pipelines.yml',
    'netlify.toml', 'vercel.json', 'fly.toml'
]

def get_repo_structure(repo_path: str, max_depth: int = 3) -> str:
    """
    Generate a tree-like string representation of the repository structure.
    """
    output = []
    start_level = repo_path.rstrip(os.sep).count(os.sep)
    
    for root, dirs, files in os.walk(repo_path):
        level = root.count(os.sep) - start_level
        if level > max_depth:
            continue
            
        indent = "  " * level
        basename = os.path.basename(root)
        
        # Skip hidden directories and ignored patterns
        if basename.startswith('.') and basename != '.github':
            dirs[:] = []
            continue
            
        if any(fnmatch.fnmatch(basename, p) for p in IGNORE_PATTERNS):
            dirs[:] = []
            continue
            
        output.append(f"{indent}{basename}/")
        
        subindent = "  " * (level + 1)
        for f in files:
            if any(fnmatch.fnmatch(f, p) for p in IGNORE_PATTERNS):
                continue
            output.append(f"{subindent}{f}")
            
    return "\n".join(output)

def get_config_files(repo_path: str) -> Dict[str, str]:
    """
    Read the content of key configuration files.
    """
    configs = {}
    
    for root, _, files in os.walk(repo_path):
        # Limit depth for config search to avoid deep nested node_modules etc
        if root.count(os.sep) - repo_path.count(os.sep) > 3:
            continue
            
        for f in files:
            # Check if file matches any config pattern
            matched = False
            for pattern in CONFIG_FILES:
                if fnmatch.fnmatch(f, pattern) or fnmatch.fnmatch(os.path.join(root, f), pattern):
                    matched = True
                    break
            
            if matched:
                rel_path = os.path.relpath(os.path.join(root, f), repo_path)
                try:
                    with open(os.path.join(root, f), 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        # Truncate large files
                        if len(content) > 5000:
                            content = content[:5000] + "\n... (truncated)"
                        configs[rel_path] = content
                except Exception:
                    pass
                    
    return configs

def get_repo_context(repo_path: str) -> Tuple[str, Dict[str, str]]:
    """
    Get both structure and config files for a repository.
    """
    if not os.path.exists(repo_path):
        return "Repository path not found.", {}
        
    structure = get_repo_structure(repo_path)
    configs = get_config_files(repo_path)
    
    return structure, configs

import subprocess
import shutil
import tempfile
import logging

logger = logging.getLogger(__name__)

def clone_repo_to_temp(repo_url: str, token: str = None) -> str:
    """
    Clone a repository to a temporary directory.
    Returns the path to the temporary directory.
    """
    temp_dir = tempfile.mkdtemp(prefix="auditgh_arch_")
    
    try:
        if not repo_url:
            raise ValueError("Repository URL is required")

        # Insert token into URL if provided
        if token and "github.com" in repo_url and "@" not in repo_url:
            auth_url = repo_url.replace("https://", f"https://x-access-token:{token}@")
        else:
            auth_url = repo_url
            
        logger.info(f"Cloning {repo_url} to {temp_dir}...")
        subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, temp_dir],
            check=True,
            capture_output=True
        )
        return temp_dir
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone repository: {e.stderr.decode()}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {e.stderr.decode()}")

def cleanup_repo(repo_path: str):
    """
    Remove the temporary repository directory.
    """
    if os.path.exists(repo_path) and "auditgh_arch_" in repo_path:
        shutil.rmtree(repo_path, ignore_errors=True)
