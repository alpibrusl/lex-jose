# SD-JWT tests: issue → present → verify round-trip, concealment of withheld
# claims, forged-disclosure rejection, duplicate-claim rejection, and
# tampered-token rejection. HS256 keeps the vectors cheap; the SD mechanics
# are algorithm-independent.

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "../src/jwa" as jwa

import "../src/sd_jwt" as sd

fn secret() -> Bytes {
  bytes.from_str("sd-jwt-test-secret")
}

fn given_name() -> sd.Disclosure {
  sd.make_disclosure("c2FsdA", "given_name", "\"alice\"")
}

fn age() -> sd.Disclosure {
  sd.make_disclosure("c2FsdB", "age", "41")
}

fn issued() -> Result[Str, Str] {
  sd.issue(HS256, secret(), "{\"iss\":\"issuer-1\"}", [given_name(), age()])
}

fn full_roundtrip() -> Result[Unit, Str] {
  match issued() {
    Err(e) => Err(str.concat("issue: ", e)),
    Ok(tok) => match sd.verify(HS256, secret(), tok) {
      Err(e) => Err(str.concat("verify: ", e)),
      Ok(v) => if list.len(v.disclosed) == 2 {
        Ok(())
      } else {
        Err("expected both claims disclosed")
      },
    },
  }
}

fn present_subset_conceals_the_rest() -> Result[Unit, Str] {
  match issued() {
    Err(e) => Err(str.concat("issue: ", e)),
    Ok(tok) => match sd.present(tok, ["age"]) {
      Err(e) => Err(str.concat("present: ", e)),
      Ok(pres) => match sd.verify(HS256, secret(), pres) {
        Err(e) => Err(str.concat("verify: ", e)),
        Ok(v) => match list.head(v.disclosed) {
          None => Err("age should be disclosed"),
          Some(d) => if list.len(v.disclosed) == 1 {
            if d.claim == "age" {
              if d.value_json == "41" {
                Ok(())
              } else {
                Err("age value mangled")
              }
            } else {
              Err("wrong claim disclosed")
            }
          } else {
            Err("given_name should stay concealed")
          },
        },
      },
    },
  }
}

fn forged_disclosure_rejected() -> Result[Unit, Str] {
  match issued() {
    Err(e) => Err(str.concat("issue: ", e)),
    Ok(tok) => match sd.present(tok, []) {
      Err(e) => Err(str.concat("present: ", e)),
      Ok(bare) => {
        let forged := sd.make_disclosure("c2FsdC", "role", "\"admin\"")
        let with_forged := str.join([bare, forged.encoded, "~"], "")
        match sd.verify(HS256, secret(), with_forged) {
          Ok(_) => Err("forged disclosure admitted"),
          Err(_) => Ok(()),
        }
      },
    },
  }
}

fn duplicate_claim_rejected() -> Result[Unit, Str] {
  let d1 := sd.make_disclosure("c2FsdA", "role", "\"user\"")
  let d2 := sd.make_disclosure("c2FsdB", "role", "\"admin\"")
  match sd.issue(HS256, secret(), "{}", [d1, d2]) {
    Err(e) => Err(str.concat("issue: ", e)),
    Ok(tok) => match sd.verify(HS256, secret(), tok) {
      Ok(_) => Err("duplicate claim admitted"),
      Err(_) => Ok(()),
    },
  }
}

fn tampered_token_rejected() -> Result[Unit, Str] {
  match issued() {
    Err(e) => Err(str.concat("issue: ", e)),
    Ok(tok) => match sd.verify(HS256, bytes.from_str("wrong-secret"), tok) {
      Ok(_) => Err("verified under the wrong secret"),
      Err(_) => Ok(()),
    },
  }
}

fn run_all() -> Unit {
  let results := [full_roundtrip(), present_subset_conceals_the_rest(), forged_disclosure_rejected(), duplicate_claim_rejected(), tampered_token_rejected()]
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

