# lex-jose

**Part of the [Lex](https://lexlang.org) project** — [Manifesto](https://www.lexlang.org/manifesto) · [All packages](https://lexlang.org)

JOSE for Lex — JSON Web Signature, Token, and Key (JWS / JWT / JWK), built in pure Lex on top of `std.crypto`.

```
import "lex-jose/jwt" as jwt

# Sign a claims document (HMAC or Ed25519), verify it back.
match jwt.encode(EdDSA, secret_seed, "{\"sub\":\"agent-1\"}") {
  Ok(token) => jwt.decode(EdDSA, public_key, token),  # -> Ok(claims_json)
  Err(e)    => Err(e),
}
```

## Why it exists

`std.crypto` provides the primitives (HMAC, Ed25519, SHA-256, base64url, and — on
`lex-lang` main — P-256/ES256). lex-jose is the standards layer on top: the JOSE
serializations every JWT/SD-JWT consumer needs, in one place, so packages like
[lex-guard](https://github.com/alpibrusl/lex-guard) (AP2 payment mandates) and
[lex-robot](https://github.com/alpibrusl/lex-robot) (signed A2A agent cards) don't
each reinvent it.

## Algorithms

| Alg | Type | Status |
|-----|------|--------|
| `HS256` / `HS512` | HMAC (symmetric) | ✅ available |
| `EdDSA` (Ed25519) | asymmetric | ✅ available |
| `ES256` (ECDSA P-256) | asymmetric | ⏳ pending — needs the `std.crypto` P-256 primitive ([lex-lang #652](https://github.com/alpibrusl/lex-lang/pull/652)), which is on `main` but not yet in a released toolchain. The API accepts `ES256`; sign/verify return an error until the primitive ships. |

## Modules

- **`jwa`** — algorithm identifiers (`Alg`), `alg_supported`, `is_symmetric`.
- **`jws`** — JWS Compact Serialization: `sign_compact` / `verify_compact`.
- **`jwt`** — JWT over JWS: `encode` / `decode` (claims as a JSON string, so any claim set works).
- **`jwk`** — OKP (Ed25519) JWK publishing + RFC 7638 thumbprints (key IDs).

## Security

Verification re-derives the protected header and **requires `header.alg` to equal
the expected algorithm** — the defense against algorithm-substitution attacks
(`alg: none`, HS↔asymmetric key confusion). A token signed under one algorithm
will not verify when a different algorithm is expected.

## Relationship to lex-crypto

[lex-crypto](https://github.com/alpibrusl/lex-crypto) keeps the **symmetric,
session-oriented** helpers (HS256 JWT with fixed claims, OAuth2, cookies, TOTP,
password hashing). lex-jose owns the **standards JOSE stack** — asymmetric
algorithms, arbitrary claims, JWK, and (next) SD-JWT. The boundary is deliberate:
symmetric-simple → lex-crypto; standards-full → lex-jose. HS256 is not
reimplemented across both.

## Roadmap

- **ES256** sign/verify + EC P-256 JWKs, once `std.crypto` P-256 lands in a release.
- **SD-JWT** (selective disclosure + key binding / proof-of-possession) — the AP2 mandate format. Disclosure/`_sd` digest mechanics are algorithm-independent (SHA-256) and work over EdDSA today; ES256 is the interop target.
- **exp / nbf** time-based claim validation in `jwt.decode`.
- **JWS JSON Serialization** (in addition to Compact).

## License

[EUPL-1.2](https://eupl.eu/).
