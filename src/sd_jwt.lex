# SD-JWT — selective disclosure over JWS (draft-ietf-oauth-selective-disclosure-jwt),
# the AP2 mandate format.
#
# A disclosure is base64url(`["<salt>","<claim>",<value>]`). The issuer signs a
# JWT whose `_sd` array holds base64url(SHA-256(disclosure)) digests, and hands
# the holder the combined serialization:
#
#   <jwt>~<disclosure-1>~...~<disclosure-n>~
#
# The holder re-serializes with any SUBSET of the disclosures (`present`); the
# verifier checks the JWT signature, then admits exactly those disclosures whose
# digest the signed `_sd` covers (`verify`). Digest membership is checked BEFORE
# a disclosure is parsed — an attacker-crafted disclosure never reaches the
# parser with its output trusted.
#
# Scope notes for v0.1:
# - Object-property disclosures only (no array-element `...` disclosures yet).
# - No key-binding JWT yet; the combined serialization always ends with `~`.
# - Salts and claim names must be escape-free JSON strings (true for anything
#   this module mints — salts are base64url); `parse_disclosure` rejects a
#   disclosure carrying a backslash in either.

import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.list" as list

import "std.json" as json

import "./jwa" as jwa

import "./jwt" as jwt

# A disclosure with everything derived from it. `encoded` is the wire form;
# `digest` is what the signed `_sd` array carries.
type Disclosure = { salt_b64 :: Str, claim :: Str, value_json :: Str, encoded :: Str, digest :: Str }

# One claim recovered by `verify`.
type DisclosedClaim = { claim :: Str, value_json :: Str }

# What `verify` returns: the signed payload plus the admitted claims.
type SdVerified = { payload_json :: Str, disclosed :: List[DisclosedClaim] }

# Internal parse target for the signed payload's SD fields.
type SdPayload = { _sd :: List[Str], _sd_alg :: Str }

# Parsed pieces of one disclosure.
type DisclosureParts = { salt_b64 :: Str, claim :: Str, value_json :: Str }

# ── Disclosure construction ──────────────────────────────────────────────────
# The wire form: base64url of the three-element JSON array. `value_json` is
# spliced verbatim, so any JSON value works ("\"alice\"", "41", objects...).
fn encode_disclosure(salt_b64 :: Str, claim :: Str, value_json :: Str) -> Str
  examples {
    encode_disclosure("c2FsdA", "given_name", "\"alice\"") => "WyJjMkZzZEEiLCJnaXZlbl9uYW1lIiwiYWxpY2UiXQ",
    encode_disclosure("c2FsdA", "age", "41") => "WyJjMkZzZEEiLCJhZ2UiLDQxXQ"
  }
{
  crypto.base64url_encode(bytes.from_str(str.join(["[\"", salt_b64, "\",\"", claim, "\",", value_json, "]"], "")))
}

# base64url(SHA-256(ascii(encoded))) — the digest the `_sd` array carries.
fn digest_of(encoded :: Str) -> Str
  examples {
    digest_of("WyJjMkZzZEEiLCJnaXZlbl9uYW1lIiwiYWxpY2UiXQ") => "vish69UD8LZwoh4saIhOCDmuUjFh9n8nzQIh6vx4wU0",
    digest_of("WyJjMkZzZEEiLCJhZ2UiLDQxXQ") => "Mg_NfKNnLC_UwoCwd2xzCJLnD-XrjbR-at0ZN5mS-uM"
  }
{
  crypto.base64url_encode(crypto.sha256(bytes.from_str(encoded)))
}

# Assemble a Disclosure from an explicit salt. Deterministic — the two pure
# fns above carry the vectors; this is their record assembly.
fn make_disclosure(salt_b64 :: Str, claim :: Str, value_json :: Str) -> Disclosure {
  let encoded := encode_disclosure(salt_b64, claim, value_json)
  { salt_b64: salt_b64, claim: claim, value_json: value_json, encoded: encoded, digest: digest_of(encoded) }
}

# Mint a disclosure with a fresh 128-bit salt (the spec's recommended size).
fn conceal(claim :: Str, value_json :: Str) -> [random] Disclosure {
  make_disclosure(crypto.base64url_encode(crypto.random(16)), claim, value_json)
}

# ── Issuance ─────────────────────────────────────────────────────────────────
# Splice `_sd` (digests, sorted for a canonical payload) and `_sd_alg` into a
# JSON object of always-visible claims.
fn payload_with_sd(visible_claims_json :: Str, digests :: List[Str]) -> Result[Str, Str]
  examples {
    payload_with_sd("{\"iss\":\"me\"}", ["dX", "aB"]) => Ok("{\"_sd\":[\"aB\",\"dX\"],\"_sd_alg\":\"sha-256\",\"iss\":\"me\"}"),
    payload_with_sd("{}", ["aB"]) => Ok("{\"_sd\":[\"aB\"],\"_sd_alg\":\"sha-256\"}"),
    payload_with_sd("[]", ["aB"]) => Err("visible claims must be a JSON object")
  }
{
  let n := str.len(visible_claims_json)
  if n >= 2 {
    if str.slice(visible_claims_json, 0, 1) == "{" {
      if str.slice(visible_claims_json, n - 1, n) == "}" {
        let sorted := list.sort_by(digests, fn (d :: Str) -> Str {
          d
        })
        let quoted := list.map(sorted, fn (d :: Str) -> Str {
          str.join(["\"", d, "\""], "")
        })
        let sd_fields := str.join(["\"_sd\":[", str.join(quoted, ","), "],\"_sd_alg\":\"sha-256\""], "")
        let inner := str.slice(visible_claims_json, 1, n - 1)
        if str.is_empty(inner) {
          Ok(str.join(["{", sd_fields, "}"], ""))
        } else {
          Ok(str.join(["{", sd_fields, ",", inner, "}"], ""))
        }
      } else {
        Err("visible claims must be a JSON object")
      }
    } else {
      Err("visible claims must be a JSON object")
    }
  } else {
    Err("visible claims must be a JSON object")
  }
}

# Combined serialization: token ~ d1 ~ ... ~ dn ~ (trailing `~`, no KB-JWT).
fn serialize(token :: Str, encoded :: List[Str]) -> Str
  examples {
    serialize("t", ["d1", "d2"]) => "t~d1~d2~",
    serialize("t", []) => "t~"
  }
{
  str.concat(str.join(list.cons(token, encoded), "~"), "~")
}

# Sign an SD-JWT: visible claims stay in the payload, each Disclosure's digest
# goes into `_sd`, and the combined serialization carries all disclosures.
fn issue(alg :: jwa.Alg, key :: Bytes, visible_claims_json :: Str, ds :: List[Disclosure]) -> Result[Str, Str] {
  let digests := list.map(ds, fn (d :: Disclosure) -> Str {
    d.digest
  })
  match payload_with_sd(visible_claims_json, digests) {
    Err(e) => Err(e),
    Ok(payload) => match jwt.encode(alg, key, payload) {
      Err(e) => Err(e),
      Ok(token) => Ok(serialize(token, list.map(ds, fn (d :: Disclosure) -> Str {
        d.encoded
      }))),
    },
  }
}

# ── Presentation ─────────────────────────────────────────────────────────────
# Split a combined serialization into token + non-empty disclosure segments.
fn split_serialized(s :: Str) -> { token :: Str, encoded :: List[Str] }
  examples {
    split_serialized("t~d1~d2~") => { token: "t", encoded: ["d1", "d2"] },
    split_serialized("t~") => { token: "t", encoded: [] }
  }
{
  let parts := str.split(s, "~")
  match list.head(parts) {
    None => { token: "", encoded: [] },
    Some(token) => { token: token, encoded: list.filter(list.tail(parts), fn (p :: Str) -> Bool {
      if str.is_empty(p) {
        false
      } else {
        true
      }
    }) },
  }
}

# Re-serialize with only the disclosures whose claim name is in `keep`. The
# holder's move: everything else stays concealed behind its digest.
fn present(issued :: Str, keep :: List[Str]) -> Result[Str, Str] {
  let parts := split_serialized(issued)
  if str.is_empty(parts.token) {
    Err("empty SD-JWT serialization")
  } else {
    match keep_matching(parts.encoded, keep) {
      Err(e) => Err(e),
      Ok(kept) => Ok(serialize(parts.token, kept)),
    }
  }
}

fn keep_matching(encoded :: List[Str], keep :: List[Str]) -> Result[List[Str], Str] {
  list.fold(encoded, Ok([]), fn (acc :: Result[List[Str], Str], e :: Str) -> Result[List[Str], Str] {
    match acc {
      Err(x) => Err(x),
      Ok(xs) => match parse_disclosure(e) {
        Err(er) => Err(er),
        Ok(p) => if contains_str(keep, p.claim) {
          Ok(list.concat(xs, [e]))
        } else {
          Ok(xs)
        },
      },
    }
  })
}

# ── Verification ─────────────────────────────────────────────────────────────
# Verify a presentation: JWT signature + header alg first, then every
# presented disclosure must hash into the signed `_sd` (checked before the
# disclosure is parsed), with duplicate digests and claim names rejected.
fn verify(alg :: jwa.Alg, key :: Bytes, presentation :: Str) -> Result[SdVerified, Str] {
  let parts := split_serialized(presentation)
  match jwt.decode(alg, key, parts.token) {
    Err(e) => Err(e),
    Ok(payload) => match (json.parse_strict(payload, ["_sd", "_sd_alg"]) :: Result[SdPayload, Str]) {
      Err(e) => Err(str.concat("payload is not an SD-JWT: ", e)),
      Ok(sd) => if sd._sd_alg == "sha-256" {
        match admit_disclosures(parts.encoded, sd._sd) {
          Err(e) => Err(e),
          Ok(disclosed) => Ok({ payload_json: payload, disclosed: disclosed }),
        }
      } else {
        Err(str.concat("unsupported _sd_alg: ", sd._sd_alg))
      },
    },
  }
}

fn admit_disclosures(encoded :: List[Str], sd :: List[Str]) -> Result[List[DisclosedClaim], Str] {
  list.fold(encoded, Ok([]), fn (acc :: Result[List[DisclosedClaim], Str], e :: Str) -> Result[List[DisclosedClaim], Str] {
    match acc {
      Err(x) => Err(x),
      Ok(admitted) => if contains_str(sd, digest_of(e)) {
        match parse_disclosure(e) {
          Err(er) => Err(er),
          Ok(p) => if claim_seen(admitted, p.claim) {
            Err(str.concat("duplicate disclosed claim: ", p.claim))
          } else {
            Ok(list.concat(admitted, [{ claim: p.claim, value_json: p.value_json }]))
          },
        }
      } else {
        Err("disclosure digest not covered by the token's _sd")
      },
    }
  })
}

fn claim_seen(admitted :: List[DisclosedClaim], claim :: Str) -> Bool {
  list.fold(admitted, false, fn (seen :: Bool, d :: DisclosedClaim) -> Bool {
    if seen {
      true
    } else {
      d.claim == claim
    }
  })
}

fn contains_str(xs :: List[Str], x :: Str) -> Bool
  examples {
    contains_str(["a", "b"], "b") => true,
    contains_str(["a", "b"], "c") => false
  }
{
  list.fold(xs, false, fn (seen :: Bool, y :: Str) -> Bool {
    if seen {
      true
    } else {
      y == x
    }
  })
}

# ── Disclosure parsing ───────────────────────────────────────────────────────
# First occurrence of `pat` in `s` at or after `from`.
fn find_from(s :: Str, pat :: Str, from :: Int) -> Option[Int]
  examples {
    find_from("ab,cd", ",", 0) => Some(2),
    find_from("ab,cd", ",", 3) => None
  }
{
  if from + str.len(pat) > str.len(s) {
    None
  } else {
    if str.slice(s, from, from + str.len(pat)) == pat {
      Some(from)
    } else {
      find_from(s, pat, from + 1)
    }
  }
}

fn has_backslash(s :: Str) -> Bool
  examples {
    has_backslash("plain") => false,
    has_backslash("a\\b") => true
  }
{
  if list.len(str.split(s, "\\")) == 1 {
    false
  } else {
    true
  }
}

# Recover `["<salt>","<claim>",<value>]` from the wire form. Escape-free salts
# and claim names only (see the module header): a backslash in either segment
# is rejected rather than interpreted.
fn parse_disclosure(encoded :: Str) -> Result[DisclosureParts, Str]
  examples {
    parse_disclosure("WyJjMkZzZEEiLCJnaXZlbl9uYW1lIiwiYWxpY2UiXQ") => Ok({ salt_b64: "c2FsdA", claim: "given_name", value_json: "\"alice\"" }),
    parse_disclosure("WyJjMkZzZEEiLCJhZ2UiLDQxXQ") => Ok({ salt_b64: "c2FsdA", claim: "age", value_json: "41" }),
    parse_disclosure("!!!") => Err("bad disclosure encoding")
  }
{
  match crypto.base64url_decode(encoded) {
    Err(_) => Err("bad disclosure encoding"),
    Ok(raw) => match bytes.to_str(raw) {
      Err(_) => Err("disclosure is not valid UTF-8"),
      Ok(s) => parse_disclosure_json(s),
    },
  }
}

fn parse_disclosure_json(s :: Str) -> Result[DisclosureParts, Str] {
  let n := str.len(s)
  if n >= 9 {
    if str.slice(s, 0, 2) == "[\"" {
      if str.slice(s, n - 1, n) == "]" {
        match find_from(s, "\",\"", 2) {
          None => Err("malformed disclosure: missing salt/claim separator"),
          Some(i1) => match find_from(s, "\",", i1 + 3) {
            None => Err("malformed disclosure: missing claim/value separator"),
            Some(i2) => finish_parts(str.slice(s, 2, i1), str.slice(s, i1 + 3, i2), str.slice(s, i2 + 2, n - 1)),
          },
        }
      } else {
        Err("malformed disclosure: not a JSON array")
      }
    } else {
      Err("malformed disclosure: not a JSON array")
    }
  } else {
    Err("malformed disclosure: too short")
  }
}

fn finish_parts(salt_b64 :: Str, claim :: Str, value_json :: Str) -> Result[DisclosureParts, Str] {
  if has_backslash(salt_b64) {
    Err("disclosure salt contains an escape")
  } else {
    if has_backslash(claim) {
      Err("disclosure claim name contains an escape")
    } else {
      if str.is_empty(value_json) {
        Err("malformed disclosure: empty value")
      } else {
        Ok({ salt_b64: salt_b64, claim: claim, value_json: value_json })
      }
    }
  }
}

