Logs  Add Log Management to the auditgithub app accessible through  the Settings > Configuration page as another tab called Cribl. When clicked it takes the admin to the Cribl integration page. From there the admin can configure send logs to Cribl.   Setup a dedicated log storage space, such as a Docker container that will mimic the same capabilities as Azure Blob.  Use the Docker container as the collector source as referred to in this document. Have all the logs from the other Docker containers send and store their logs to this log storage Docker container.  UI/UX To integrate log collection into the Next.JS application and send data to Cribl Stream, you need to configure a connection between the application (the "Sender") and a Cribl Stream Source (the "Receiver").
Based on the architectural integration models, the Push-based Ingestion Model is the standard approach for real-time applications. 
Here are the specific configuration settings required for the application's UI/UX (to allow users to connect) and the corresponding settings in Cribl Stream.
1. Application Configuration (Next.JS Settings UI)
In the Next.JS application's configuration interface (e.g., an Admin or Integrations settings page), you need to capture the following parameters to establish a connection. Typically, these values are stored as environment variables (e.g., .env.local) or database settings to keep them secure.
• Cribl Endpoint URL: The full URL where the Next.JS server (or client) will POST the logs.
    ◦ Example: https://worker-group.thedomain.com:20000 or https://<uuid>.cribl.cloud:20000
    ◦ Note: In Cribl.Cloud, ports 20000–20010 are reserved for custom HTTP sources.
• Authentication Token: A security token required to authenticate requests.
    ◦ Implementation: the app must send this in the HTTP Authorization header,.
    ◦ Example Value: Bearer <the_secure_token>
• Format/Content-Type: The structure of the log payload.
    ◦ Recommendation: Use JSON (application/json) or NDJSON (Newline Delimited JSON) to allow Cribl to automatically parse fields,.
2. Cribl Stream Configuration (Receiver)
In the Cribl Stream UI, you must configure a Source to listen for these incoming requests.
A. Select the Source Type
Navigate to Data > Sources and add one of the following:
• Raw HTTP/S: Best for generic JSON payloads. It is versatile and supports arbitrary JSON.
B. Network & Security Settings
• Port: Configure the Source to listen on a specific port.
    ◦ Cribl.Cloud: You must use the reserved range 20000–20010.
• TLS Settings: Enable TLS (HTTPS) to encrypt logs in transit.
    ◦ You can use Cribl's default certificate or upload the own.
• Authentication:
    ◦ In the Source settings, define an Auth Token.
    ◦ Cribl will reject any request that does not include this token in the header, ensuring unauthorized users cannot flood the pipeline,.
3. Implementation Recommendation: Next.JS API Routes
It is highly recommended to send logs from the client (browser) to a Next.JS API Route (Server-Side) first, rather than sending directly from the browser to Cribl.
• Why: Sending directly from the browser requires exposing the Auth Token in client-side code and dealing with CORS (Cross-Origin Resource Sharing) restrictions.
• How:
    1. Client: The browser sends logs to POST /api/log.
    2. Server (Next.JS): The API route (pages/api/log.js or app/api/log/route.ts) adds the secure Auth Token and forwards the payload to the Cribl Endpoint URL.
    3. Cribl: Receives the request with the IP of the Next.JS server. If you need the original client IP, forward it in the X-Forwarded-For header. Cribl can parse this header to preserve the client's identity using the __srcIpPort internal field.  When toggled to enable, update the application's logging configuration to bypass Azure Log Analytics and send logs directly to Cribl Stream. Configure the logging transport (e.g., Winston, Pino, or a custom HTTP client) to perform a POST request with the following specifications:
• Endpoint: https://<the-cribl-worker-url>:<port>/services/collector/event (if using Splunk HEC format) or .../cribl/_bulk (if using Raw/Bulk HTTP),.
• Method: POST
• Headers: Include Authorization: Bearer <the-cribl-auth-token>,.
• Payload Format: JSON or NDJSON (Newline Delimited JSON) containing the timestamp, severity, and full message body,.
• Behavior: Ensure all log levels (System, Application, Behavioral actions) are forwarded. We will handle filtering and noise reduction downstream in Cribl."
3. Instructions for System Logs (Pull Model via the store space)
Since you mentioned the logs are maintained in a Storage Account (likely Azure Blob), you do not need to change how the system writes to that storage. Instead, you instruct Cribl to "collect" (pull) that data, replacing the process where Log Analytics reads it.
Configuration within Cribl Stream: You will configure a Collector Source to read from.
• Action: In Cribl Stream, navigate to Sources > Collectors
• Discovery: Configure Cribl to discover new log files as they land in the storage space.
• Processing: Cribl will pull these logs, parse them (using Event Breakers), and route them to the final destinations.  Summary

Setup a form to include these fields:
Field Label	Description	Example
Ingest URL	The HTTP/S address of the Cribl Source.	https://cribl.example.com:20000
Auth Token	The arbitrary token string configured in Cribl.	x8s9-f2k1-99s0
Verify SSL	(Toggle) Whether to validate the server's certificate.	True / False
 Once configured, the application simply needs to make a POST request with the JSON log body and the appropriate headers to the configured URL. Cribl Stream will handle the rest, including parsing, buffering, and routing.  Also, add a Test Configuration Button to test connectivity and settings are correctly configured and working.