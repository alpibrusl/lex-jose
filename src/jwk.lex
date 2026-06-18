# JWK — JSON Web Key (RFC 7517 / RFC 8037 OKP).
#
# v0.1 publishes Ed25519 public keys as OKP JWKs and computes RFC 7638
# thumbprints (used as key IDs, including for AP2 key binding). EC P-256 (ES256)
# JWKs arrive with the std.crypto P-256 primitive.

import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

# An Ed25519 public key as an OKP JWK. Members are emitted in lexicographic
# order with no whitespace, so this string IS the RFC 7638 canonical form.
fn okp_ed25519_public(public_key :: Bytes) -> Str {
  str.concat("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"", str.concat(crypto.base64url_encode(public_key), "\"}"))
}

# RFC 7638 JWK thumbprint: base64url(SHA-256(canonical JWK)).
fn okp_ed25519_thumbprint(public_key :: Bytes) -> Str {
  crypto.base64url_encode(crypto.sha256(bytes.from_str(okp_ed25519_public(public_key))))
}

