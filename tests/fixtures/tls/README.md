# Synthetic TLS material

The original eight static PEM files exist only for offline M3.3B tests; six
additional PEM files serve M3.4B synthetic loopback handshake tests. Every certificate
and key was generated for this repository; none is an operator credential.
The included private keys are intentionally public test inputs.

Generated once with test-setup OpenSSL CLI 3.6.4 (RSA 2048, SHA-256). Two
self-signed CAs have serials 1/2; an intermediate signed by CA 1 has serial 3;
the client leaf signed by that intermediate has serial 4. `client-chain.pem`
contains leaf plus intermediate. `mismatch-key.pem` is unrelated; the encrypted
PKCS#8 and traditional PEM files encrypt the matching client key with a synthetic test password.
Tests never supply that password. Certificates have a ten-year fixture validity
period; construction tests do not perform certificate-time verification.

Static inputs keep tests independent of the OpenSSL CLI and certificate
generation timing. Production uses only stdlib ssl, never a fixture generator,
external OpenSSL command or temporary credential file.

M3.4B's six additional static inputs were generated once with test-setup
OpenSSL CLI 3.6.4 (RSA 2048, SHA-256): `server-ca.pem` (public root, serial 100),
`server-key.pem` (intentionally public test key), `server.pem` (serial 101,
DNS SAN api.test.invalid), `wrong-host.pem` (102, wrong.test.invalid),
`ip-only.pem` (103, IP SANs 127.0.0.1 and ::1), and `untrusted-server.pem`
(201, matching DNS SAN but signed by a separate untrusted root, serial 200).
All four server leaves share the test key. The root private keys and untrusted
root certificate are disposable generation inputs, not repository fixtures.
Certificates use fixed validity from 2020-01-01 through 2120-01-01; handshake
tests verify normal certificate time and logical hostname without clock patching.
All synthetic PEM files are excluded from built wheels. No operator material,
runtime fixture generation, additional dependency or external helper is used.
