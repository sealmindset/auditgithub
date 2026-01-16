import pkgutil
import inspect
import importlib
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

def get_diagrams_index() -> Dict[str, str]:
    """
    Walks the `diagrams` package and returns a dictionary mapping
    Node class names to their full import paths.
    
    Example:
    {
        "NetworkSecurityGroup": "diagrams.azure.network.NetworkSecurityGroup",
        "EC2": "diagrams.aws.compute.EC2",
        ...
    }
    """
    index = {}
    
    try:
        import diagrams
    except ImportError:
        logger.error("diagrams library not installed.")
        return {}

    # Helper to recursively walk packages
    def walk_package(package):
        if hasattr(package, "__path__"):
            for _, name, is_pkg in pkgutil.iter_modules(package.__path__):
                full_name = f"{package.__name__}.{name}"
                try:
                    module = importlib.import_module(full_name)
                    
                    # Inspect module for Node classes
                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj):
                            # Check if it's a Node (but not the base Node class itself)
                            # We check if it belongs to the diagrams package to avoid importing builtins
                            if obj.__module__.startswith("diagrams") and name != "Node" and name != "Cluster" and name != "Edge":
                                # We only want the leaf nodes, usually they don't have subclasses in the same file
                                # But actually, we just want a mapping of Name -> Path.
                                # If there are duplicates (same name in different providers), we might overwrite.
                                # Strategy: Store all, or prioritize?
                                # For now, let's store the last one found, but maybe we should store a list?
                                # The prompt asks for "NetworkSecurityGroup", if it's unique it's easy.
                                # If it's "Database", it might be in multiple places.
                                # Let's store the full path.
                                index[name] = f"{obj.__module__}.{name}"
                    
                    if is_pkg:
                        walk_package(module)
                except Exception as e:
                    # Skip modules that fail to import (e.g. missing dependencies)
                    pass

    walk_package(diagrams)
    
    logger.info(f"Indexed {len(index)} diagram nodes.")
    return index

def search_diagram_node(index: Dict[str, str], query: str) -> List[str]:
    """
    Search for a node in the index.
    Returns a list of matching full import paths.
    """
    matches = []
    query_lower = query.lower()
    for name, path in index.items():
        if query_lower in name.lower():
            matches.append(path)
    return matches
