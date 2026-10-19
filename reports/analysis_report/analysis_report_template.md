# Network Traffic Analysis Report

**Analyst:**  
**Date:**  
**Capture:** `captures/sample_traffic.pcap`

## 1. Scope and method

State that this is a synthetic training capture and list the tools and filters used.

## 2. Key observations

| Observation | Packet number(s) | Evidence | Interpretation / confidence |
|---|---:|---|---|
| DNS request and response | | | |
| TCP three-way handshake | | | |
| HTTP request and response | | | |
| TCP connection to port 443 | | | |
| Potentially exposed plaintext | | | |

## 3. DNS analysis

- Query name:
- DNS server:
- Response / answer:
- What DNS metadata is visible?

## 4. TCP handshake

- Client IP:port:
- Server IP:port:
- SYN packet:
- SYN-ACK packet:
- Final ACK packet:
- What does a successful three-way handshake establish?

## 5. HTTP plaintext exposure

- Request method and path:
- Host:
- Demo header/value observed:
- Why is plaintext HTTP unsuitable for secrets?
- Recommended mitigation:

## 6. HTTPS metadata

Describe metadata that can remain visible (such as endpoint IPs, ports, timing, and sizes). Do not claim that the synthetic port-443 flow proves a real TLS session.

## 7. Suspicious-pattern assessment

List any unusual behavior and the evidence supporting it. If none is present, say so. Distinguish observed facts from hypotheses.

## 8. Recommendations

Examples: use HTTPS/TLS, avoid sending secrets in URLs or plaintext headers, patch systems, monitor DNS and connection patterns, and use approved monitoring practices.

## 9. Limitations

This is a small, synthetic capture. It cannot represent a real production network or establish malicious intent.
