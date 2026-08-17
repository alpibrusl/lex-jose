# JWA — JSON Web Algorithms (RFC 7518), plus the SD-JWT / AP2 target set.
#
# `alg_supported` gates the algorithms this build can actually sign/verify.
# As of toolchain v0.10.8 std.crypto carries P-256 (lex-lang #652), so all
# four algorithms — HS256, HS512, EdDSA, ES256 — are live.

type Alg = HS256 | HS512 | EdDSA | ES256

fn alg_str(a :: Alg) -> Str {
  match a {
    HS256 => "HS256",
    HS512 => "HS512",
    EdDSA => "EdDSA",
    ES256 => "ES256",
  }
}

fn alg_from_str(s :: Str) -> Option[Alg] {
  if s == "HS256" {
    Some(HS256)
  } else {
    if s == "HS512" {
      Some(HS512)
    } else {
      if s == "EdDSA" {
        Some(EdDSA)
      } else {
        if s == "ES256" {
          Some(ES256)
        } else {
          None
        }
      }
    }
  }
}

# Can this build sign/verify the algorithm?
fn alg_supported(a :: Alg) -> Bool
  examples {
    alg_supported(ES256) => true,
    alg_supported(HS256) => true
  }
{
  match a {
    HS256 => true,
    HS512 => true,
    EdDSA => true,
    ES256 => true,
  }
}

# Symmetric algorithms verify with the same secret used to sign (no public key).
fn is_symmetric(a :: Alg) -> Bool {
  match a {
    HS256 => true,
    HS512 => true,
    _ => false,
  }
}

