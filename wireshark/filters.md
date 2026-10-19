# Wireshark Display Filters

Paste these into the display-filter bar. They filter packets already captured; they do not start a capture.

| Goal | Display filter |
|---|---|
| DNS traffic | `dns` |
| TCP packets | `tcp` |
| UDP packets | `udp` |
| HTTP packets | `http` |
| Traffic to/from demo client | `ip.addr == 192.0.2.10` |
| DNS server traffic | `ip.addr == 203.0.113.53` |
| TCP port 80 | `tcp.port == 80` |
| TCP port 443 | `tcp.port == 443` |
| SYN packets | `tcp.flags.syn == 1` |
| SYN without ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| TCP resets | `tcp.flags.reset == 1` |
| DNS errors (if present) | `dns.flags.rcode != 0` |
| HTTP methods | `http.request.method` |
| HTTP responses | `http.response` |

## Guided investigation

1. Apply `dns`. Identify the query name and the response address.
2. Apply `tcp.flags.syn == 1`. Find the SYN, SYN-ACK, ACK sequence for the HTTP connection.
3. Apply `http`. Inspect the request method, host, path, and demo header. Explain why this is visible.
4. Apply `tcp.port == 443`. Record what metadata remains visible even though application data should be encrypted in a real HTTPS session.
5. Review **Statistics → Conversations**. Are there repeated connections, unusual ports, or unexpected destinations in this small synthetic capture?

## Caution

A display filter is not the same as a capture filter. Avoid concluding that traffic is malicious from a port number or one packet alone.
