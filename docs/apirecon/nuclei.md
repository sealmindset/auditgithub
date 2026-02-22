id: api-cors-ratelimit-check
info:
  name: API Protocol & Security Header Analysis
  author: iAPI-Bot
  severity: info
  description: Checks for CORS permissive configurations and Rate Limit header disclosure.

requests:
  - raw:
      - |
        OPTIONS {{BaseURL}}/api/ HTTP/1.1
        Host: {{Hostname}}
        Origin: [https://evil.com](https://evil.com)
        Access-Control-Request-Method: POST
        Access-Control-Request-Headers: X-Custom-Header

    matchers-condition: or
    matchers:
      # Heuristic 1: CORS Misconfiguration (Reflects Origin)
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: [https://evil.com](https://evil.com)"
          - "Access-Control-Allow-Credentials: true"
        condition: and

      # Heuristic 2: Rate Limit Exposure (Useful for attackers to throttle)
      - type: word
        part: header
        words:
          - "X-RateLimit-Limit"
          - "X-RateLimit-Remaining"
          - "X-RateLimit-Reset"
        condition: or

      # Heuristic 3: Check for Success Status on OPTIONS
      - type: status
        status:
          - 200
          - 204