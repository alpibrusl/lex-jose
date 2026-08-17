# DER — ECDSA-Sig-Value conversion between DER (what std.crypto's P-256
# primitives emit and accept) and the raw 64-byte R||S concatenation JWS
# requires for ES256 (RFC 7518 §3.4). Pure byte surgery, fully deterministic.
#
# DER shape (RFC 3279 ECDSA-Sig-Value; always short-form lengths here, since
# a P-256 signature never exceeds 72 bytes):
#
#   0x30 <seq_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
#
# DER integers are minimal-length big-endian with a single 0x00 pad byte when
# the high bit is set. The raw form is fixed-width: 32-byte R then 32-byte S.

import "std.bytes" as bytes

import "std.crypto" as crypto

# ── raw → DER ─────────────────────────────────────────────────────────────────
# Drop leading zero bytes, keeping at least one byte.
# Bytes-level helper; test vectors live on the *_hex wrappers below.
fn strip_leading_zeros(b :: Bytes) -> Bytes {
  if bytes.len(b) <= 1 {
    b
  } else {
    match bytes.u8_at(b, 0) {
      Err(_) => b,
      Ok(v) => if v == 0 {
        strip_leading_zeros(bytes.slice(b, 1, bytes.len(b)))
      } else {
        b
      },
    }
  }
}

# Bytes-level helper; test vectors live on the *_hex wrappers below.
fn high_bit_set(b :: Bytes) -> Bool {
  match bytes.u8_at(b, 0) {
    Err(_) => false,
    Ok(v) => v >= 128,
  }
}

# One DER INTEGER (0x02) from a fixed-width big-endian value.
# Bytes-level helper; test vectors live on the *_hex wrappers below.
fn der_int(v :: Bytes) -> Bytes {
  let stripped := strip_leading_zeros(v)
  let content := if high_bit_set(stripped) {
    bytes.concat(bytes.u8(0), stripped)
  } else {
    stripped
  }
  bytes.concat_all([bytes.u8(2), bytes.u8(bytes.len(content)), content])
}

# 64-byte R||S → DER ECDSA-Sig-Value.
# Bytes-level; test vectors live on raw_to_der_hex below.
fn raw_to_der(raw :: Bytes) -> Result[Bytes, Str] {
  if bytes.len(raw) == 64 {
    let body := bytes.concat(der_int(bytes.slice(raw, 0, 32)), der_int(bytes.slice(raw, 32, 64)))
    Ok(bytes.concat_all([bytes.u8(48), bytes.u8(bytes.len(body)), body]))
  } else {
    Err("raw ECDSA signature must be exactly 64 bytes")
  }
}

# ── DER → raw ─────────────────────────────────────────────────────────────────
# Left-pad with zeros to exactly 32 bytes; a value wider than 32 bytes is not
# a P-256 scalar. Bytes-level helper; vectors live on the *_hex wrappers.
fn to_fixed_32(v :: Bytes) -> Result[Bytes, Str] {
  let stripped := strip_leading_zeros(v)
  if bytes.len(stripped) > 32 {
    Err("DER integer wider than 32 bytes")
  } else {
    Ok(pad_to_32(stripped))
  }
}

# Bytes-level helper; test vectors live on the *_hex wrappers below.
fn pad_to_32(v :: Bytes) -> Bytes {
  if bytes.len(v) >= 32 {
    v
  } else {
    pad_to_32(bytes.concat(bytes.u8(0), v))
  }
}

# Parse one DER INTEGER at `off`; returns its content bytes and next offset.
# Bytes-level helper; test vectors live on the *_hex wrappers below.
fn parse_int(der :: Bytes, off :: Int) -> Result[{ value :: Bytes, next :: Int }, Str] {
  match bytes.u8_at(der, off) {
    Err(_) => Err("truncated DER integer tag"),
    Ok(tag) => if tag == 2 {
      match bytes.u8_at(der, off + 1) {
        Err(_) => Err("truncated DER integer length"),
        Ok(len) => if off + 2 + len <= bytes.len(der) {
          Ok({ value: bytes.slice(der, off + 2, off + 2 + len), next: off + 2 + len })
        } else {
          Err("DER integer overruns the signature")
        },
      }
    } else {
      Err("expected DER INTEGER (0x02)")
    },
  }
}

# DER ECDSA-Sig-Value → 64-byte R||S.
# Bytes-level; test vectors live on der_to_raw_hex below.
fn der_to_raw(der :: Bytes) -> Result[Bytes, Str] {
  match bytes.u8_at(der, 0) {
    Err(_) => Err("empty DER signature"),
    Ok(tag) => if tag == 48 {
      match bytes.u8_at(der, 1) {
        Err(_) => Err("truncated DER sequence length"),
        Ok(seq_len) => if 2 + seq_len == bytes.len(der) {
          match parse_int(der, 2) {
            Err(e) => Err(e),
            Ok(r) => match parse_int(der, r.next) {
              Err(e) => Err(e),
              Ok(s) => if s.next == bytes.len(der) {
                match to_fixed_32(r.value) {
                  Err(e) => Err(e),
                  Ok(r32) => match to_fixed_32(s.value) {
                    Err(e) => Err(e),
                    Ok(s32) => Ok(bytes.concat(r32, s32)),
                  },
                }
              } else {
                Err("trailing bytes after DER integers")
              },
            },
          }
        } else {
          Err("DER sequence length does not match signature length")
        },
      }
    } else {
      Err("expected DER SEQUENCE (0x30)")
    },
  }
}

# ── Hex wrappers — carry the test vectors for the whole module ───────────────
fn raw_to_der_hex(raw_hex :: Str) -> Result[Str, Str]
  examples {
    raw_to_der_hex("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002") => Ok("3006020101020102"),
    raw_to_der_hex("00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001") => Ok("300702020080020101"),
    raw_to_der_hex("0101") => Err("raw ECDSA signature must be exactly 64 bytes")
  }
{
  match crypto.hex_decode(raw_hex) {
    Err(e) => Err(e),
    Ok(raw) => match raw_to_der(raw) {
      Err(e) => Err(e),
      Ok(der) => Ok(crypto.hex_encode(der)),
    },
  }
}

fn der_to_raw_hex(der_hex :: Str) -> Result[Str, Str]
  examples {
    der_to_raw_hex("3006020101020102") => Ok("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"),
    der_to_raw_hex("300702020080020101") => Ok("00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001"),
    der_to_raw_hex("3106020101020102") => Err("expected DER SEQUENCE (0x30)"),
    der_to_raw_hex("3007020101020102") => Err("DER sequence length does not match signature length")
  }
{
  match crypto.hex_decode(der_hex) {
    Err(e) => Err(e),
    Ok(der) => match der_to_raw(der) {
      Err(e) => Err(e),
      Ok(raw) => Ok(crypto.hex_encode(raw)),
    },
  }
}

