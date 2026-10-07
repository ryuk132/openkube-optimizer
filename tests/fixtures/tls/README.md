# Synthetic TLS material

These eight static files exist only for offline M3.3B tests. Every certificate
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
