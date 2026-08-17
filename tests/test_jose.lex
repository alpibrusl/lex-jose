# lex-jose tests: JWS/JWT round-trips for all four algorithms (HS256, HS512,
# EdDSA, ES256), the algorithm-substitution defense, tamper/wrong-key
# rejection, and JWK thumbprint determinism.

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "std.crypto" as crypto

import "../src/jwa" as jwa

import "../src/jws" as jws

import "../src/jwt" as jwt

import "../src/jwk" as jwk

fn secret() -> Bytes {
  bytes.from_str("hmac-secret-key-material")
}

fn seed() -> Bytes {
  bytes.from_str("0123456789abcdef0123456789abcdef")
}

fn claims() -> Str {
  "{\"sub\":\"agent-1\",\"scope\":\"spend\"}"
}

fn hs256_roundtrip() -> Result[Unit, Str] {
  match jwt.encode(HS256, secret(), claims()) {
    Err(e) => Err(str.concat("encode: ", e)),
    Ok(tok) => match jwt.decode(HS256, secret(), tok) {
      Err(e) => Err(str.concat("decode: ", e)),
      Ok(got) => if got == claims() {
        Ok(())
      } else {
        Err("claims mismatch")
      },
    },
  }
}

fn hs256_wrong_secret_rejected() -> Result[Unit, Str] {
  match jwt.encode(HS256, secret(), claims()) {
    Err(e) => Err(str.concat("encode: ", e)),
    Ok(tok) => match jwt.decode(HS256, bytes.from_str("a-different-secret-entirely"), tok) {
      Ok(_) => Err("verified under wrong secret"),
      Err(_) => Ok(()),
    },
  }
}

fn eddsa_roundtrip() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(seed()) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pk) => match jws.sign_compact(EdDSA, seed(), "JWT", bytes.from_str(claims())) {
      Err(e) => Err(str.concat("sign: ", e)),
      Ok(tok) => match jws.verify_compact(EdDSA, pk, tok) {
        Err(e) => Err(str.concat("verify: ", e)),
        Ok(payload) => match bytes.to_str(payload) {
          Err(e) => Err(str.concat("utf8: ", e)),
          Ok(got) => if got == claims() {
            Ok(())
          } else {
            Err("payload mismatch")
          },
        },
      },
    },
  }
}

fn eddsa_tamper_rejected() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(seed()) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pk) => match jws.sign_compact(EdDSA, seed(), "JWT", bytes.from_str(claims())) {
      Err(e) => Err(str.concat("sign: ", e)),
      Ok(tok) => match jws.verify_compact(EdDSA, pk, str.concat(tok, "Z")) {
        Ok(_) => Err("tampered token verified"),
        Err(_) => Ok(()),
      },
    },
  }
}

# Sign with HS256, try to verify as EdDSA: the header-alg check must reject it.
fn alg_substitution_rejected() -> Result[Unit, Str] {
  match jwt.encode(HS256, secret(), claims()) {
    Err(e) => Err(str.concat("encode: ", e)),
    Ok(tok) => match jws.verify_compact(EdDSA, seed(), tok) {
      Ok(_) => Err("alg substitution accepted"),
      Err(_) => Ok(()),
    },
  }
}

fn es256_roundtrip() -> Result[Unit, Str] {
  match crypto.p256_public_key(seed()) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pk) => match jwt.encode(ES256, seed(), claims()) {
      Err(e) => Err(str.concat("encode: ", e)),
      Ok(tok) => match jwt.decode(ES256, pk, tok) {
        Err(e) => Err(str.concat("decode: ", e)),
        Ok(got) => if got == claims() {
          Ok(())
        } else {
          Err("claims mismatch")
        },
      },
    },
  }
}

fn es256_tamper_rejected() -> Result[Unit, Str] {
  match crypto.p256_public_key(seed()) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pk) => match jws.sign_compact(ES256, seed(), "JWT", bytes.from_str(claims())) {
      Err(e) => Err(str.concat("sign: ", e)),
      Ok(tok) => match jws.verify_compact(ES256, pk, str.concat(tok, "Z")) {
        Ok(_) => Err("tampered ES256 token verified"),
        Err(_) => Ok(()),
      },
    },
  }
}

fn es256_wrong_key_rejected() -> Result[Unit, Str] {
  match crypto.p256_public_key(bytes.from_str("fedcba9876543210fedcba9876543210")) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(other_pk) => match jwt.encode(ES256, seed(), claims()) {
      Err(e) => Err(str.concat("encode: ", e)),
      Ok(tok) => match jwt.decode(ES256, other_pk, tok) {
        Ok(_) => Err("ES256 verified under the wrong public key"),
        Err(_) => Ok(()),
      },
    },
  }
}

# Sign with EdDSA, try to verify as ES256: the header-alg check must reject it.
fn es256_substitution_rejected() -> Result[Unit, Str] {
  match crypto.p256_public_key(seed()) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pk) => match jwt.encode(EdDSA, seed(), claims()) {
      Err(e) => Err(str.concat("encode: ", e)),
      Ok(tok) => match jws.verify_compact(ES256, pk, tok) {
        Ok(_) => Err("EdDSA token accepted as ES256"),
        Err(_) => Ok(()),
      },
    },
  }
}

fn jwk_thumbprint_deterministic() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(seed()) {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pk) => if jwk.okp_ed25519_thumbprint(pk) == jwk.okp_ed25519_thumbprint(pk) {
      Ok(())
    } else {
      Err("thumbprint not deterministic")
    },
  }
}

fn run_all() -> Unit {
  let results := [hs256_roundtrip(), hs256_wrong_secret_rejected(), eddsa_roundtrip(), eddsa_tamper_rejected(), alg_substitution_rejected(), es256_roundtrip(), es256_tamper_rejected(), es256_wrong_key_rejected(), es256_substitution_rejected(), jwk_thumbprint_deterministic()]
  let failures := list.fold(results, 0, fn (n :: Int, r :: Result[Unit, Str]) -> Int {
    match r {
      Ok(_) => n,
      Err(_) => n + 1,
    }
  })
  if failures == 0 {
    ()
  } else {
    let __discard := 1 / 0
    ()
  }
}

