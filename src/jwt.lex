# JWT — JSON Web Token (RFC 7519) as a JWS-signed claims document.
#
# Claims travel as a JSON string so any claim set works (AP2 mandates carry
# non-standard claims). The signature and the protected header's `alg` are
# verified by the JWS layer. Time-based validation (exp / nbf) is the next
# addition — see the README roadmap.

import "std.bytes" as bytes

import "./jwa" as jwa

import "./jws" as jws

# Sign a claims JSON document as a JWT (typ "JWT").
fn encode(alg :: jwa.Alg, key :: Bytes, claims_json :: Str) -> Result[Str, Str] {
  jws.sign_compact(alg, key, "JWT", bytes.from_str(claims_json))
}

# Verify a JWT's signature + header alg; return the claims JSON on success.
# `key` is the HMAC secret (HS*) or the Ed25519 public key (EdDSA).
fn decode(alg :: jwa.Alg, key :: Bytes, token :: Str) -> Result[Str, Str] {
  match jws.verify_compact(alg, key, token) {
    Err(e) => Err(e),
    Ok(payload) => bytes.to_str(payload),
  }
}

