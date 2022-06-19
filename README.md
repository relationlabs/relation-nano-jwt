# nano-jwt

A nano JWT(JSON Web Tokens) is a pure Rust implementation focuses on simplicity and easy use.

| JWT algorithm name | Description               |
|--------------------|---------------------------|
| `ES256`            | ECDSA over p256 / SHA-256 |
| ...                | ...                       |

## Examples

1. Generate Elliptic Curve keys

Use the following commands to generate a P-256 Elliptic Curve key pair:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out es256_private.pem
openssl ec -in es256_private.pem -pubout -out es256_public.pem
```

2. Convert to `PKCS#8` format

```bash
openssl pkcs8 -topk8 -nocrypt -in es256_private.pem -out es256_private_pkcs8.pem
```

3. Run Example

```bash
cargo run --example es256_example
```