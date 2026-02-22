For discovering API services, endpoints, and reverse engineering paths/parameters/values, several open-source CLI tools stand out for their effectiveness in tasks like traffic analysis, fuzzing, enumeration, and schema extraction. These are free, community-maintained, and can be installed via package managers like brew, apt, or go. Here’s a curated list of the best ones based on popularity, features, and relevance:

1. mitmproxy/mitmproxy2swagger

A powerful HTTP/HTTPS proxy for intercepting and analyzing API traffic. mitmproxy2swagger specifically automates reverse-engineering REST APIs by capturing requests and generating OpenAPI specs. Ideal for reconstructing undocumented endpoints and parameters from live traffic. 30 38

2. ffuf

A fast web fuzzer in Go, excellent for brute-forcing and discovering hidden API paths, endpoints, and parameters through wordlists and pattern matching. It’s lightweight and supports custom payloads for value enumeration. 22 38

3. kiterunner

A contextual content discovery tool tailored for APIs, using curated wordlists for endpoint enumeration across REST, GraphQL, and other protocols. It excels at scanning for paths and values in large API surfaces quickly. 22 38

4. Arjun

An HTTP parameter discovery suite focused on brute-forcing query strings, JSON bodies, and headers to uncover hidden values and paths in APIs. Supports multiple methods and is great for reverse-engineering request structures. 38

5. Akto

An API discovery and testing tool that scans for endpoints via traffic analysis or specs, with runtime detection for paths and sensitive values. It includes CLI modes for automated inventory building and logic probing. 19 21 25 38

6. gobuster

A directory and endpoint brute-forcer similar to ffuf, but with modes for DNS, vhost, and fuzzing API routes. Useful for initial discovery of service paths in web APIs. 22

7. APIKit

An all-in-one toolkit for API discovery, scanning, and auditing. It enumerates endpoints, parameters, and values from specs or traffic, with CLI support for quick reverse-engineering. 30 38

8. getallurls (gau)

Fetches known URLs and endpoints from public sources like Common Crawl, Wayback Machine, and OTX. Great for passive reconnaissance and discovering historical API paths without direct interaction. 38

Additional Essentials

curl/httpie: Basic CLI HTTP clients for manual probing of endpoints and values. httpie is more user-friendly for JSON-heavy APIs. 9 27 
jq: A JSON processor for parsing and extracting values from API responses during reverse-engineering. 27 
Start with mitmproxy for traffic-based reverse-engineering, then use fuzzers like ffuf or kiterunner for active discovery. Always ensure ethical use, such as on APIs you own or have permission to test.