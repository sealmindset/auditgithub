
Regex Patterns for Hardcoded Secret Detection
(Saved responses are view only)
Here are the key regular expression (regex) patterns used by security researchers to hunt for hardcoded secrets, tokens, and credentials within JavaScript files:
1. Generic Secret and Token Detectors When developers use custom names for variables holding sensitive information, broad patterns are used to catch them:
• Catch-all for API keys and secrets: (?i)(api_key|token|access_token|secret|key)["']?\s*[:=]\s*["']([^"']+)['"] or (?i)(apikey|api_key|secret|token)['"\s:=]+[a-zA-Z0-9\-._]{8,}
• Authorization Bearer Tokens: Bearer\s+[a-zA-Z0-9\-._~+/]+=*
• High Entropy Base64 Strings (often used for generic encryption keys or payloads): ['\"][A-Za-z0-9+\/]{40,}={0,2}['\"]
2. Platform-Specific API Keys and Tokens Many cloud providers and services have distinct, recognizable formats for their keys that can be easily parsed using regex:
• Google API Key: AIza[0-9A-Za-z\\-_]{35}
• AWS Access Key ID: AKIA[0-9A-Z]{16}
• AWS Secret Access Key: (?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]
• GitHub Token: ghp_[0-9a-zA-Z]{36}
• Slack Token: xox[baprs]-([0-9a-zA-Z]{10,48})?
• Stripe Secret Key: sk_live_[0-9a-zA-Z]{24}
• Twilio API Key: SK[0-9a-fA-F]{32}
• Firebase Secret: AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
3. Authentication & Cryptographic Material Regex is also highly effective at discovering authentication flows and private keys:
• JSON Web Tokens (JWT): eyJ[a-zA-Z0-9-_=]+?\.[a-zA-Z0-9-_=]+\.?[a-zA-Z0-9-_.+/=]*
• OAuth Client Secret: (?i)client_secret['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}
• Private Key Blocks: -----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----
• Basic Auth Credentials (Username and Password combinations): (?i)(username|user|email)['"\s:=]+[^\s'"@]{1,100}['"].*?(password|pwd)['"\s:=]+[^\s'"]{4,100}
4. Database Connections Developers sometimes inadvertently leak connection strings containing database credentials:
• MongoDB URI: mongodb(\+srv)?:\/\/[^\s'"]+
• PostgreSQL URI: postgres(?:ql)?:\/\/[^\s'"]+
• Redis URI: redis:\/\/[^\s'"]+
Security teams typically combine these regex patterns with automated tools and static analysis pipelines to pull these exposed secrets out of minified or obfuscated JavaScript code