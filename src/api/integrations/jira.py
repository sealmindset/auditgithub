import logging
import requests
from requests.auth import HTTPBasicAuth
from typing import Optional, Dict, Any
from ..config import settings

logger = logging.getLogger(__name__)

class JiraClient:
    def __init__(self):
        self.url = settings.JIRA_URL
        self.username = settings.JIRA_USERNAME
        self.token = settings.JIRA_API_TOKEN
        self.project_key = settings.JIRA_PROJECT_KEY
        self.enabled = bool(self.url and self.username and self.token)

    def create_issue(self, summary: str, description: str, issuetype: str = "Bug", priority: str = "Medium", labels: list = None) -> Optional[Dict[str, Any]]:
        """Create a new issue in Jira."""
        if not self.enabled:
            logger.warning("Jira integration is not enabled")
            return None

        endpoint = f"{self.url}/rest/api/3/issue"
        
        # Map priority to Jira ID if necessary, or use name
        # This is a simplified payload
        payload = {
            "fields": {
                "project": {
                    "key": self.project_key
                },
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": issuetype
                },
                # "priority": { "name": priority } # Uncomment if priority scheme matches
            }
        }
        
        if labels:
            payload["fields"]["labels"] = labels

        try:
            response = requests.post(
                endpoint,
                json=payload,
                auth=HTTPBasicAuth(self.username, self.token),
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to create Jira issue: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response: {e.response.text}")
            return None

    def get_issue(self, issue_key: str) -> Optional[Dict[str, Any]]:
        """Get issue details."""
        if not self.enabled: return None
        
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(self.username, self.token),
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get Jira issue {issue_key}: {e}")
            return None

    def add_comment(self, issue_key: str, comment: str) -> bool:
        """Add a comment to an issue."""
        if not self.enabled: return False
        
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}/comment"
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": comment
                            }
                        ]
                    }
                ]
            }
        }
        
        try:
            response = requests.post(
                endpoint,
                json=payload,
                auth=HTTPBasicAuth(self.username, self.token),
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to add comment to {issue_key}: {e}")
            return False

jira_client = JiraClient()
