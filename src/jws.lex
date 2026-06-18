# JWS — JSON Web Signature, Compact Serialization (RFC 7515).
#
#   BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
#
# Signs/verifies over the signing input `header.payload`. Verification re-derives
# the protected header and REQUIRES header.alg to equal the expected algorithm —
# this is the defense against algorithm-substitution ("alg: none" / HS↔RS swap)
# attacks. Built directly on std.crypto primitives.

import "std.str" as str

import "std.json" as json

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.list" as list

import "./jwa" as jwa

# The protected header we emit and validate.
type Header = { alg :: Str, typ :: Str }

fn header_json(alg :: jwa.Alg, typ :: Str) -> Str {
  str.concat("{\"alg\":\"", str.concat(jwa.alg_str(alg), str.concat("\",\"typ\":\"", str.concat(typ, "\"}"))))
}

# Raw signature bytes over the signing input, dispatched by algorithm.
# `key` is the HMAC secret (HS*) or the 32-byte Ed25519 seed (EdDSA).
fn sign_bytes(alg :: jwa.Alg, key :: Bytes, signing_input :: Str) -> Result[Bytes, Str] {
  match alg {
    HS256 => Ok(crypto.hmac_sha256(key, bytes.from_str(signing_input))),
    HS512 => Ok(crypto.hmac_sha512(key, bytes.from_str(signing_input))),
    EdDSA => crypto.ed25519_sign(key, bytes.from_str(signing_input)),
    ES256 => Err("ES256 not supported in this build (needs std.crypto P-256, lex-lang #652)"),
  }
}

# Produce a JWS compact token over `payload`.
fn sign_compact(alg :: jwa.Alg, key :: Bytes, typ :: Str, payload :: Bytes) -> Result[Str, Str] {
  let header_b64 := crypto.base64url_encode(bytes.from_str(header_json(alg, typ)))
  let payload_b64 := crypto.base64url_encode(payload)
  let signing_input := str.concat(header_b64, str.concat(".", payload_b64))
  match sign_bytes(alg, key, signing_input) {
    Err(e) => Err(e),
    Ok(sig) => Ok(str.concat(signing_input, str.concat(".", crypto.base64url_encode(sig)))),
  }
}

# Verify a JWS compact token. `key` is the HMAC secret (HS*) or the 32-byte
# Ed25519 PUBLIC key (EdDSA). On success returns the decoded payload bytes.
fn verify_compact(alg :: jwa.Alg, key :: Bytes, token :: Str) -> Result[Bytes, Str] {
  let parts := str.split(token, ".")
  if list.len(parts) == 3 {
    match list.head(parts) {
      None => Err("malformed JWS"),
      Some(header_b64) => match list.head(list.tail(parts)) {
        None => Err("malformed JWS"),
        Some(payload_b64) => match list.head(list.tail(list.tail(parts))) {
          None => Err("malformed JWS"),
          Some(sig_b64) => verify_parts(alg, key, header_b64, payload_b64, sig_b64),
        },
      },
    }
  } else {
    Err("malformed JWS: expected three '.'-separated segments")
  }
}

fn verify_parts(alg :: jwa.Alg, key :: Bytes, header_b64 :: Str, payload_b64 :: Str, sig_b64 :: Str) -> Result[Bytes, Str] {
  match check_header_alg(alg, header_b64) {
    Err(e) => Err(e),
    Ok(_) => {
      let signing_input := str.concat(header_b64, str.concat(".", payload_b64))
      match verify_sig(alg, key, signing_input, sig_b64) {
        Err(e) => Err(e),
        Ok(ok) => if ok {
          decode_payload(payload_b64)
        } else {
          Err("invalid signature")
        },
      }
    },
  }
}

# Reject the token unless its protected header names exactly the expected alg.
fn check_header_alg(alg :: jwa.Alg, header_b64 :: Str) -> Result[Unit, Str] {
  match crypto.base64url_decode(header_b64) {
    Err(_) => Err("bad header encoding"),
    Ok(hbytes) => match bytes.to_str(hbytes) {
      Err(_) => Err("header is not valid UTF-8"),
      Ok(hjson) => match (json.parse(hjson) :: Result[Header, Str]) {
        Err(e) => Err(str.concat("bad header json: ", e)),
        Ok(h) => if h.alg == jwa.alg_str(alg) {
          Ok(())
        } else {
          Err(str.concat("algorithm mismatch: header says ", h.alg))
        },
      },
    },
  }
}

fn verify_sig(alg :: jwa.Alg, key :: Bytes, signing_input :: Str, sig_b64 :: Str) -> Result[Bool, Str] {
  match alg {
    HS256 => Ok(recompute_eq(crypto.hmac_sha256(key, bytes.from_str(signing_input)), sig_b64)),
    HS512 => Ok(recompute_eq(crypto.hmac_sha512(key, bytes.from_str(signing_input)), sig_b64)),
    EdDSA => match crypto.base64url_decode(sig_b64) {
      Err(_) => Err("bad signature encoding"),
      Ok(sig) => Ok(crypto.ed25519_verify(key, bytes.from_str(signing_input), sig)),
    },
    ES256 => Err("ES256 not supported in this build (needs std.crypto P-256, lex-lang #652)"),
  }
}

fn recompute_eq(expected :: Bytes, sig_b64 :: Str) -> Bool {
  crypto.base64url_encode(expected) == sig_b64
}

fn decode_payload(payload_b64 :: Str) -> Result[Bytes, Str] {
  match crypto.base64url_decode(payload_b64) {
    Err(_) => Err("bad payload encoding"),
    Ok(p) => Ok(p),
  }
}

