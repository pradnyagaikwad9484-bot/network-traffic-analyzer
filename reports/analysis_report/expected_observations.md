# Expected observations (answer key)

Use this only after attempting the lab.

- DNS query: `training.example.test`, from `192.0.2.10` to `203.0.113.53` over UDP/53.
- DNS response: the demo name resolves to `198.51.100.20` in this synthetic capture.
- TCP handshake: client `192.0.2.10:51514` to server `198.51.100.20:80`; flags are SYN, SYN-ACK, ACK.
- HTTP request: `GET /training-page`; the fake `X-Demo-Token` header is visible because the payload is plaintext.
- Port 443 flow: endpoint/port/timing metadata remains visible. This sample does not contain a full TLS handshake, so do not call it a validated HTTPS session.
- The capture is intentionally small and contains no real malicious activity. There is not enough evidence to label a host malicious.
