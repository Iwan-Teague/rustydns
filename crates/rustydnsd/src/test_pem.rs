//! Self-signed test cert chain, embedded for DoT integration tests.
//!
//! Generated once with:
//!
//! ```sh
//! # CA
//! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//!     -subj /CN=rustydns-test-ca \
//!     -keyout ca-key.pem -out ca-cert.pem
//! # Leaf CSR
//! openssl req -newkey rsa:2048 -nodes \
//!     -subj /CN=rustydns-dot-test \
//!     -keyout leaf-key.pem -out leaf.csr
//! # Sign leaf with CA, attach SAN + leaf extensions
//! cat > leaf.ext <<EOF
//! basicConstraints=CA:FALSE
//! keyUsage=digitalSignature,keyEncipherment
//! extendedKeyUsage=serverAuth
//! subjectAltName=DNS:rustydns-dot-test
//! EOF
//! openssl x509 -req -in leaf.csr -CA ca-cert.pem -CAkey ca-key.pem \
//!     -CAcreateserial -out leaf-cert.pem -days 3650 -extfile leaf.ext
//! ```
//!
//! Tests put `TEST_CA_PEM` in the client's `RootCertStore` and feed
//! `TEST_LEAF_CERT_PEM` + `TEST_LEAF_KEY_PEM` to `load_tls_config()`
//! on the server side. The leaf's CN/SAN is `rustydns-dot-test`, so
//! the client dials it by that name.
//!
//! Two pairs of constants because rustls 0.23 rejects a self-signed
//! CA cert as an end-entity (`CaUsedAsEndEntity`); we need a proper
//! chain with the leaf carrying `BasicConstraints=CA:FALSE`.

#[allow(dead_code)]
pub(crate) const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUVrf+S+fOZpT+/ywOEG8uPVc/NEUwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQcnVzdHlkbnMtdGVzdC1jYTAeFw0yNjA1MjIxMTE4MTda
Fw0zNjA1MTkxMTE4MTdaMBsxGTAXBgNVBAMMEHJ1c3R5ZG5zLXRlc3QtY2EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVvd2PqYvLY8JisZxKcGCbleLM
/xmKrBA9CUGQ/iQarBcH4EWH5J8ClyN3MukXrzhgOy9hq0g1Psp4FjNEDumnzXLj
UJ/cwXC/VHzxjz98lnWPBSqboPaw9Bv3QMmsDc1oeDnnwXTBMGRGgTNYPIf3ten/
Eq98IZ9a134wNpBh/7A7egEW/dMHO9n2SuEla8L8S3PjJy6aFH5YL6kcS+oQDwth
k3l2G8d/XbNroERdp7EQ6LHhule4m6meFNQgbmLbYQp4wbfU2bx09jHxVvmpJ86V
povuGl2nThT6BrTIgbfJD4EnzSKkVtqeP11K87tu2m3mE3wOMkQsP/Y7TCs/AgMB
AAGjUzBRMB0GA1UdDgQWBBRgNUwJwGUG5QAcxRvv11Xx00LU6DAfBgNVHSMEGDAW
gBRgNUwJwGUG5QAcxRvv11Xx00LU6DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQB47q7B4QOEoKjEeOe4awpMO0D1JWfHWkiaLaa/z9LbTOppPJJo
j8o2lPdI0/X6bRQ8mPy7asTZlHu+52gICxl2zMCAE7abHhxUuGepiPDIZbneiXVQ
AAHK1WrONe7RHOLbrBdmXV7e5ozPi3QnCBGgsiBIwyc9jPgSb9g6qyUqaa4Hd09S
Flr9WAOXlQreDThvhiZc9/0aGrIyZICftLtOIiyhYlmxz8+3fXT08NAy5xmfOOTO
o7R0hOm/d5NN+P4u/ueCVhrFTpdkRbGsZbb1/Q4bNHNRnQvimrkwgyuBI506DhRZ
zS38BLLM3HLUqKK1s+4On9+pXGCodL0rmzEO
-----END CERTIFICATE-----
";

/// Leaf cert (CN + SAN `rustydns-dot-test`, `CA:FALSE`).
pub(crate) const TEST_LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIUD/Rv2thax08S1PiGFeLELeprrOAwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQcnVzdHlkbnMtdGVzdC1jYTAeFw0yNjA1MjIxMTE4MTha
Fw0zNjA1MTkxMTE4MThaMBwxGjAYBgNVBAMMEXJ1c3R5ZG5zLWRvdC10ZXN0MIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzAOrBViykZAT9qUOlqxWFplL
u3qJBfcWLhLqr/PkgAwCJK44N89+FuLwxYHmbXa9TC5h61qLeBm/k+KvDJhoisKN
uB/TcAa7FsfTYTfInlGmRfl3Kz2KQgUZglTbr1fG1JgEBo4IWN886q6YlfZLoeMJ
NZrVBOFFLMsfZK0W1SJhbwixMq435LiyGlz1VciGAD/H3wCGs2klth75cZX75gyi
AD4Rwn6OXGA32DoxoR3XK66i4ySbKsUNW+PnX+BNRZhYkyPDpqkVlKtU5U/EWBCQ
YHtVtY5vY0SlSSr/SYs0VWZyF+RHSo3xieXDvRD20OK5v0JcDpHtu9ENBsS8kwID
AQABo4GOMIGLMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMBwGA1UdEQQVMBOCEXJ1c3R5ZG5zLWRvdC10ZXN0MB0GA1UdDgQWBBSt
3Dtz0Wuzeje6r+hpZAsrL0gjLDAfBgNVHSMEGDAWgBRgNUwJwGUG5QAcxRvv11Xx
00LU6DANBgkqhkiG9w0BAQsFAAOCAQEAb+CXmpziUNC8jhQwfWtsGm4SmzVzNvTN
TArnH3xD/bOQbzQMfRCrOMGNb7YwBW0Jp2y5YlvT2WgtRaoi9usZHndUPgQhYKAE
ke3LTIZG0yi+/PhmNc2Gnd3n+H3g6zMUDP/6BlS0Q738UbfXU1LEbjQmUx/8SloC
qug4pOX4doXBfmf/Q1+lfg6c0ciU5JODviQcAaMEzSj71Ry4StTesrhRpJaXDsnA
XRif63sRrQqc5z7oAgpJYt9vOQeAnG+aR0JMB8ZkTmwC2uUXQsbUqQf1AqtMyi06
taGavpVENcKYaL1yX1M7azcvq2gy7AgSF7Ce8tQ1CAls3ScWQzu/DQ==
-----END CERTIFICATE-----
";

pub(crate) const TEST_LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMA6sFWLKRkBP2
pQ6WrFYWmUu7eokF9xYuEuqv8+SADAIkrjg3z34W4vDFgeZtdr1MLmHrWot4Gb+T
4q8MmGiKwo24H9NwBrsWx9NhN8ieUaZF+XcrPYpCBRmCVNuvV8bUmAQGjghY3zzq
rpiV9kuh4wk1mtUE4UUsyx9krRbVImFvCLEyrjfkuLIaXPVVyIYAP8ffAIazaSW2
HvlxlfvmDKIAPhHCfo5cYDfYOjGhHdcrrqLjJJsqxQ1b4+df4E1FmFiTI8OmqRWU
q1TlT8RYEJBge1W1jm9jRKVJKv9JizRVZnIX5EdKjfGJ5cO9EPbQ4rm/QlwOke27
0Q0GxLyTAgMBAAECggEAAa3bpknQzNWBV8IlOMsNH/B93BQp6CYP3t81YuKNNE4x
y+vj9vZuB9gxIFI6YePcf2UEvBnDR7P5v+JzJS8xi3rTppSBRzNdYaM3zSpwkng1
9+6rf9KcC03cpBYr6YLw1jOBTPocSkb3SsmXF4NIcHoPsfFzsWLKEMO3OKGBrGb+
E18ETXZhlkpricwITj/q9d7VKppYxrnG9Hjn8PTuUXmPs6adgj7ygSv88IVcHsvA
UXiPaatS+01JquAWXTj57pGb5GpcvDylypb2nhKEsIc2tB0If5F6cV4AGbQCfbfS
1kUBeY1NgqMANjdFfkqnOqoL+G25/Rm3p5CwzF5VAQKBgQDqFEzIIHjI1LW/Nwab
RG7TIoIkpfOTRl++8UuILSO8ilbrrBbX9XiRJ0PKmILLBJuCuvxZT37rB3BIzRSQ
YewiqhopUsXty3obVQb8078YZFLTDWA1ReALSvkv9yF6NWH3tRgRmeVmnvr9y7eP
nEnSjD3Kq0tCWJOUDd5JacAvEwKBgQDfHpsIc788DmT82LhbEqsKY2RM1Bi7GpK2
enlznE7my3z2A7NAmynkeL7IUhVyf1Wpw1WzTdDaRS9J8Dg1Pj450hmikWcQ5aIB
61/O5FGRWjTBJ/J+yUwMXfIbMSR63JQLIOchS5qEb7i1Fmq1/xtHVTgjiHs4pGIJ
t6f798tsgQKBgCyr4RdUMxjIl0K9opIhFjFO5Z1O2lQh2wXakLqVOruxfvMM7XMb
Un4JC0PvpQ5Pe8oQGzaEGEmMKt6J3MHNHj5jTgjS1hkSeuQabvHzCwYBp1jFtbWU
9zPQhAumUwo6g869DbHWN9RExMuIhChxABmhT+2MkRlBRDC+EMzb1KRnAoGBAL/V
FaCHvAULr0JBpwgOneZZnFP+C6Fa8IdZ9/AxlRkUHcV7WvQSNEuOkSG0iWIfHuzN
2HJIVmhEEat1kS4d7OxTutyuPTom5UrXL1G3tnXNZAwqp3Dg67S6VT2R2/aSjeqf
iHl1Ak4ZrGpt8qO1yaNkHtdWMfN6ShxmvlSCMXGBAoGAGbadOh3SeK248Nf1BLQe
SFMVEab6i5U3X1dDOI3ng3f1/WPpLPEHmmcjDSi56blGhc40AVOgKUtOHMpDeBOG
Kvj6jJ1PCGGhqLRuauZ5mHmwUWGY4lAd7JnODOzX3F7xZmQbXatrrYMv9eLhIyKm
BpAEd//y/6xocGSJAREx9k8=
-----END PRIVATE KEY-----
";

/// Backwards-compat aliases: existing cert-error tests use the old
/// names. The cert/key pair is functionally interchangeable for the
/// load_tls_config tests, which only care that the PEM parses.
#[allow(dead_code)]
pub(crate) const TEST_CERT_PEM: &str = TEST_LEAF_CERT_PEM;
#[allow(dead_code)]
pub(crate) const TEST_KEY_PEM: &str = TEST_LEAF_KEY_PEM;

/// CN of the leaf cert. Use with `rustls::pki_types::ServerName`.
#[allow(dead_code)]
pub(crate) const TEST_CERT_CN: &str = "rustydns-dot-test";
