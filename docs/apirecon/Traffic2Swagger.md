import json
import re
from urllib.parse import urlparse

class TrafficToOpenAPI:
    def __init__(self):
        self.paths = {}
        self.definitions = {}

    def normalize_path(self, path):
        """
        Converts /users/123/orders to /users/{id}/orders
        Heuristic: Path segments that are integers or UUIDs are parameters.
        """
        segments = path.strip('/').split('/')
        normalized_segments = []
        
        uuid_regex = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        
        for segment in segments:
            if segment.isdigit():
                normalized_segments.append("{id}")
            elif re.match(uuid_regex, segment):
                normalized_segments.append("{uuid}")
            else:
                normalized_segments.append(segment)
                
        return "/" + "/".join(normalized_segments)

    def infer_schema(self, data):
        """Recursively builds a JSON schema from a data payload."""
        if isinstance(data, dict):
            properties = {k: self.infer_schema(v) for k, v in data.items()}
            return {"type": "object", "properties": properties}
        elif isinstance(data, list):
            if data:
                return {"type": "array", "items": self.infer_schema(data[0])}
            else:
                return {"type": "array", "items": {}}
        elif isinstance(data, int):
            return {"type": "integer"}
        elif isinstance(data, bool):
            return {"type": "boolean"}
        else:
            return {"type": "string"}

    def process_traffic(self, log_entry):
        """
        Ingests a traffic log (dict) containing: url, method, response_body
        """
        parsed_url = urlparse(log_entry['url'])
        path = self.normalize_path(parsed_url.path)
        method = log_entry['method'].lower()
        
        if path not in self.paths:
            self.paths[path] = {}
        
        # Build Operation Object
        operation = {
            "summary": f"Auto-discovered {method} {path}",
            "responses": {
                "200": {
                    "description": "OK",
                    "content": {
                        "application/json": {
                            "schema": {}
                        }
                    }
                }
            }
        }

        # If we have response data, infer the schema
        if log_entry.get('response_body'):
            try:
                body_json = json.loads(log_entry['response_body'])
                schema = self.infer_schema(body_json)
                operation["responses"]["200"]["content"]["application/json"]["schema"] = schema
            except json.JSONDecodeError:
                pass # Not JSON

        self.paths[path][method] = operation

    def generate_spec(self):
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Reverse-Engineered Shadow API",
                "version": "1.0.0"
            },
            "paths": self.paths
        }

# --- Example Usage ---
# Simulated Traffic Log
traffic_logs = [
    {"url": "[https://api.test.com/users/4521/profile](https://api.test.com/users/4521/profile)", "method": "GET", "response_body": '{"id": 4521, "role": "admin", "active": true}'},
    {"url": "[https://api.test.com/users/9999/profile](https://api.test.com/users/9999/profile)", "method": "GET", "response_body": '{"id": 9999, "role": "user", "active": false}'},
    {"url": "[https://api.test.com/v1/auth](https://api.test.com/v1/auth)", "method": "POST", "response_body": '{"token": "eyJ..."}'}
]

parser = TrafficToOpenAPI()
for log in traffic_logs:
    parser.process_traffic(log)

print(json.dumps(parser.generate_spec(), indent=2))