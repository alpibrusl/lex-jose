# lex-jose

**Part of the [Lex](https://lexlang.org) project** — [Manifesto](https://www.lexlang.org/manifesto) · [All packages](https://lexlang.org)

JOSE for Lex — JSON Web Signature, Token, and Key (JWS / JWT / JWK) plus SD-JWT
selective disclosure and AP2 mandate types, built in pure Lex on top of `std.crypto`.

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
| `ES256` (ECDSA P-256) | asymmetric | ✅ available (toolchain ≥ v0.10.8 carries the `std.crypto` P-256 primitive from [lex-lang #652](https://github.com/alpibrusl/lex-lang/pull/652)). Keys: 32-byte secret scalar to sign, 33-byte compressed public point to verify. JWS signatures travel as raw 64-byte R\|\|S per RFC 7518 §3.4; `src/der.lex` converts to/from the DER form the primitive speaks. |

## Modules

- **`jwa`** — algorithm identifiers (`Alg`), `alg_supported`, `is_symmetric`.
- **`jws`** — JWS Compact Serialization: `sign_compact` / `verify_compact`.
- **`jwt`** — JWT over JWS: `encode` / `decode` (claims as a JSON string, so any claim set works).
- **`jwk`** — OKP (Ed25519) JWK publishing + RFC 7638 thumbprints (key IDs).
- **`der`** — ECDSA-Sig-Value DER ↔ raw 64-byte R||S conversion for ES256.
- **`sd_jwt`** — SD-JWT selective disclosure: `conceal` / `make_disclosure`,
  `issue`, `present` (holder picks the subset), `verify` (digest membership is
  checked against the signed `_sd` before a disclosure is parsed).
- **`mandate`** — AP2 `CheckoutMandate` / `PaymentMandate`: `seal_*` /
  `verify_*`, hash binding of a payment to the literal checkout token it
  accepts, re-derived totals (a lying `total_cents` is unsealable and
  unverifiable), integer cents throughout, expiry checked against a
  caller-supplied `now` so verification stays pure.

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

- **SD-JWT key binding** (KB-JWT / proof-of-possession) and array-element
  (`...`) disclosures — v0.1 ships object-property disclosures without KB.
- **EC P-256 JWKs** — needs a point-decompression primitive in `std.crypto`
  (the 33-byte compressed point can't yield the JWK `x`/`y` pair in pure Lex).
- **exp / nbf** time-based claim validation in `jwt.decode` (the `mandate`
  module already checks expiry for its own types).
- **JWS JSON Serialization** (in addition to Compact).

## License

[EUPL-1.2](https://eupl.eu/).
