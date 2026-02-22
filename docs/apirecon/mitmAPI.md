Using mitmproxy and OWASP ZAP together is a solid approach for API discovery and reverse engineering, especially when you want to combine mitmproxy’s strengths (clean traffic capture, excellent flow scripting in Python, lightweight CLI, and tools like mitmproxy2swagger for auto-generating OpenAPI specs) with ZAP’s features (GUI-driven exploration, built-in spidering/crawling, passive/active scanning, site tree visualization, and automated vulnerability checks).

They can work together effectively, but the best setup depends on your workflow and goals.

Recommended Approach: Use Them in Serial (Chained / Sequential), Not Parallel

Serial/chained is usually better and more practical for most API reverse-engineering scenarios:

Configure your client (browser, mobile app, script, etc.) → point to mitmproxy as the proxy (default port 8080).
In mitmproxy, set an upstream proxy to forward all traffic to ZAP (running on a different port, e.g., 8081 or the default ZAP port).
Command example for mitmproxy:
mitmproxy --mode upstream:http://127.0.0.1:8081 --listen-port 8080

(Or use --upstream in older versions; check current docs for exact flag.)
ZAP then forwards traffic to the real target API/server.
Why serial/chained usually wins:

Clean separation of concerns — mitmproxy handles pure capture + scripting + export (e.g., to HAR or mitmproxy2swagger for OpenAPI generation).
ZAP gets full visibility of the same traffic for its Sites tree, history, spider, fuzzing, and passive scanning without you duplicating proxy setup on the client.
Easier certificate management — install only one CA (typically mitmproxy’s) on the client/device; ZAP can work without its own CA being trusted if it’s just receiving already-decrypted traffic from mitmproxy.
Avoids race conditions, port conflicts, double decryption overhead, or weird behavior from two tools trying to MITM the same connection simultaneously.
You get the best of both: mitmproxy’s CLI/scriptability + ZAP’s GUI/powerful automation for API exploration.
When Parallel (Running Both Independently) Makes Sense

Run both proxies at the same time (different ports) and switch your client between them manually (or use system proxy switching tools/scripts):

You want completely isolated captures (e.g., one flow in mitmproxy for scripting/export, another in ZAP for scanning).
You’re doing side-by-side comparison of how each tool interprets the same traffic.
Testing one tool’s interception behavior without interference.
Downsides of parallel:

You must reconfigure your client (or app) each time you switch → tedious, especially for mobile apps or thick clients.
Double certificate hassle if both need to MITM (you’d install both CAs).
Redundant effort — you’re capturing the same traffic twice instead of once and sharing it.
Harder to maintain consistent sessions/auth tokens across both views.
Quick Comparison Table

Aspect
Serial (mitmproxy → ZAP)
Parallel (both separate)
Setup effort
Medium (one upstream config)
Low initially, high switching
Client config changes
Only once
Frequent switching
Certificate trust
Usually one CA (mitmproxy’s)
Both CAs needed
Best for API discovery
Yes — capture once, analyze twice
Only if isolation/comparison needed
Overhead / complexity
Low
Higher (two full MITM stacks)
Recommended for most cases
Yes
Rarely
Practical Tips for Chaining

Start ZAP first (headless or GUI) on its port.
Launch mitmproxy with upstream pointing to ZAP.
Use mitmproxy’s flow filtering/scripting if you want to clean/modify traffic before ZAP sees it.
Export from mitmproxy (e.g., mitmdump -r flows -w output.har) for later import into ZAP if needed, or just let ZAP build its Sites tree live.
For pure API reverse-engineering → lean on mitmproxy + mitmproxy2swagger after capture; use ZAP mainly if you want automated crawling of discovered endpoints or vuln scanning.
Bottom line: Go serial (mitmproxy upstream to ZAP) for most efficient, low-friction API path/parameter discovery and reverse engineering. It’s the setup that gives you maximum insight with minimal hassle. Only switch to parallel if you have a very specific reason to keep the two tools completely isolated.