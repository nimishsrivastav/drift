# drift-fixture-decode-eval (SYNTHETIC)

**Synthetic test fixture. Not real malware and not a real package.**

1.0.0 is benign. 1.0.1 recreates the loader technique of flatmap-stream and similar payloads: the entry point decodes a
base64 string and passes the result to `eval` at import time, so the payload never appears as code. The encoded text is
`require('dns').lookup('sinkhole.invalid', function () {});`, a DNS lookup of the sinkhole and nothing else.
