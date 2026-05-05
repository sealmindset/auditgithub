"""
Custom brand icons for the diagrams library.

Provides PNG icons for services not included in the mingrammer/diagrams library
(e.g., Sumo Logic, CrowdTwist, Salesforce). Icons are 64x64 PNGs stored alongside
this file and copied into temp directories during diagram execution.
"""

import os
import shutil
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ICONS_DIR = os.path.join(os.path.dirname(__file__), "..", "static", "diagram_icons")

CUSTOM_BRAND_ICONS: Dict[str, Dict] = {
    "SumoLogic": {
        "label": "Sumo Logic",
        "filename": "sumo_logic.png",
        "provider": "custom",
        "category": "monitoring",
        "usage": 'Custom("Sumo Logic", "sumo_logic.png")',
    },
    "CrowdTwist": {
        "label": "CrowdTwist",
        "filename": "crowdtwist.png",
        "provider": "custom",
        "category": "loyalty",
        "usage": 'Custom("CrowdTwist", "crowdtwist.png")',
    },
    "Salesforce": {
        "label": "Salesforce",
        "filename": "salesforce.png",
        "provider": "custom",
        "category": "crm",
        "usage": 'Custom("Salesforce", "salesforce.png")',
    },
    "Tableau": {
        "label": "Tableau",
        "filename": "tableau.png",
        "provider": "custom",
        "category": "analytics",
        "usage": 'Custom("Tableau", "tableau.png")',
    },
    "Splunk": {
        "label": "Splunk",
        "filename": "splunk.png",
        "provider": "custom",
        "category": "monitoring",
        "usage": 'Custom("Splunk", "splunk.png")',
    },
    "Grafana": {
        "label": "Grafana",
        "filename": "grafana.png",
        "provider": "custom",
        "category": "monitoring",
        "usage": 'Custom("Grafana", "grafana.png")',
    },
    "GenericAnalytics": {
        "label": "Analytics",
        "filename": "generic_analytics.png",
        "provider": "custom",
        "category": "analytics",
        "usage": 'Custom("Analytics", "generic_analytics.png")',
    },
    "GenericCRM": {
        "label": "CRM",
        "filename": "generic_crm.png",
        "provider": "custom",
        "category": "crm",
        "usage": 'Custom("CRM", "generic_crm.png")',
    },
    "GenericMonitoring": {
        "label": "Monitoring",
        "filename": "generic_monitoring.png",
        "provider": "custom",
        "category": "monitoring",
        "usage": 'Custom("Monitoring", "generic_monitoring.png")',
    },
    "GenericDownstream": {
        "label": "Downstream Systems",
        "filename": "generic_downstream.png",
        "provider": "custom",
        "category": "integration",
        "usage": 'Custom("Downstream Systems", "generic_downstream.png")',
    },
}


def copy_custom_icons_to_dir(target_dir: str) -> int:
    """Copy all custom brand icon PNGs into a target directory.

    Returns the number of icons copied.
    """
    icons_dir = os.path.normpath(ICONS_DIR)
    if not os.path.isdir(icons_dir):
        logger.warning(f"Custom icons directory not found: {icons_dir}")
        return 0

    count = 0
    for entry in CUSTOM_BRAND_ICONS.values():
        src = os.path.join(icons_dir, entry["filename"])
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(target_dir, entry["filename"]))
            count += 1
    return count


def get_custom_icons_catalog() -> List[Dict]:
    """Return custom icons in catalog format for API responses."""
    catalog = []
    for name, info in CUSTOM_BRAND_ICONS.items():
        catalog.append({
            "name": name,
            "label": info["label"],
            "import_path": f'diagrams.custom.Custom("{info["label"]}", "{info["filename"]}")',
            "provider": info["provider"],
            "category": info["category"],
            "usage": f'from diagrams.custom import Custom\n{info["usage"]}',
            "is_custom": True,
        })
    return catalog


def get_custom_icons_prompt_block() -> str:
    """Return a formatted text block of custom icons for AI prompts."""
    lines = ["## Custom Brand Icons (use with `from diagrams.custom import Custom`)"]
    for name, info in CUSTOM_BRAND_ICONS.items():
        lines.append(f'- {info["label"]}: {info["usage"]}')
    return "\n".join(lines)
