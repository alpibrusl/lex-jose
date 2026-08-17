# AP2 mandate tests: the full merchant → payer → settlement flow over EdDSA
# (two distinct signers), plus every refusal path — lying totals, expiry,
# wrong-checkout binding, insufficient ceiling, wrong keys.

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "std.crypto" as crypto

import "../src/jwa" as jwa

import "../src/mandate" as m

fn merchant_seed() -> Bytes {
  bytes.from_str("merchant-signing-seed-32-bytes-x")
}

fn payer_seed() -> Bytes {
  bytes.from_str("payer-signing-seed-32-bytes-abcd")
}

fn cart() -> m.CheckoutMandate {
  { merchant_id: "bazaar-7", items: [{ sku: "olive-oil-1l", description: "olive oil, 1 l", qty: 2, unit_cents: 850 }, { sku: "bread", description: "sourdough loaf", qty: 1, unit_cents: 320 }], total_cents: 2020, currency: "EUR", expires_at: 2000 }
}

# Seal both mandates and settle at `now` = 1000, under the right keys.
fn happy_path() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(merchant_seed()) {
    Err(e) => Err(str.concat("merchant pk: ", e)),
    Ok(merchant_pk) => match crypto.ed25519_public_key(payer_seed()) {
      Err(e) => Err(str.concat("payer pk: ", e)),
      Ok(payer_pk) => match m.seal_checkout(EdDSA, merchant_seed(), cart()) {
        Err(e) => Err(str.concat("seal_checkout: ", e)),
        Ok(checkout_tok) => match m.seal_payment(EdDSA, payer_seed(), m.make_payment(checkout_tok, "card-42", 2500, 2000)) {
          Err(e) => Err(str.concat("seal_payment: ", e)),
          Ok(payment_tok) => match m.verify_checkout(EdDSA, merchant_pk, checkout_tok, 1000) {
            Err(e) => Err(str.concat("verify_checkout: ", e)),
            Ok(c) => match m.verify_payment(EdDSA, payer_pk, payment_tok, checkout_tok, 1000) {
              Err(e) => Err(str.concat("verify_payment: ", e)),
              Ok(p) => if m.payment_covers(p, c) {
                Ok(())
              } else {
                Err("2500 must cover 2020")
              },
            },
          },
        },
      },
    },
  }
}

fn lying_total_unsealable() -> Result[Unit, Str] {
  let lie := { merchant_id: "bazaar-7", items: [{ sku: "bread", description: "sourdough loaf", qty: 1, unit_cents: 320 }], total_cents: 100, currency: "EUR", expires_at: 2000 }
  match m.seal_checkout(EdDSA, merchant_seed(), lie) {
    Ok(_) => Err("sealed a checkout whose total lies about its items"),
    Err(_) => Ok(()),
  }
}

fn expired_checkout_rejected() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(merchant_seed()) {
    Err(e) => Err(str.concat("merchant pk: ", e)),
    Ok(merchant_pk) => match m.seal_checkout(EdDSA, merchant_seed(), cart()) {
      Err(e) => Err(str.concat("seal_checkout: ", e)),
      Ok(tok) => match m.verify_checkout(EdDSA, merchant_pk, tok, 2000) {
        Ok(_) => Err("expired checkout verified (expires_at = now must fail)"),
        Err(_) => Ok(()),
      },
    },
  }
}

fn wrong_checkout_binding_rejected() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(payer_seed()) {
    Err(e) => Err(str.concat("payer pk: ", e)),
    Ok(payer_pk) => match m.seal_checkout(EdDSA, merchant_seed(), cart()) {
      Err(e) => Err(str.concat("seal_checkout: ", e)),
      Ok(checkout_tok) => match m.seal_payment(EdDSA, payer_seed(), m.make_payment(checkout_tok, "card-42", 2500, 2000)) {
        Err(e) => Err(str.concat("seal_payment: ", e)),
        Ok(payment_tok) => match m.verify_payment(EdDSA, payer_pk, payment_tok, str.concat(checkout_tok, "X"), 1000) {
          Ok(_) => Err("payment verified against a different checkout token"),
          Err(_) => Ok(()),
        },
      },
    },
  }
}

fn insufficient_ceiling_flagged() -> Result[Unit, Str] {
  let p := { checkout_hash: "h", instrument_id: "card-42", max_cents: 2019, expires_at: 2000 }
  if m.payment_covers(p, cart()) {
    Err("2019 must not cover 2020")
  } else {
    Ok(())
  }
}

fn wrong_signer_rejected() -> Result[Unit, Str] {
  match crypto.ed25519_public_key(payer_seed()) {
    Err(e) => Err(str.concat("payer pk: ", e)),
    Ok(payer_pk) => match m.seal_checkout(EdDSA, merchant_seed(), cart()) {
      Err(e) => Err(str.concat("seal_checkout: ", e)),
      Ok(tok) => match m.verify_checkout(EdDSA, payer_pk, tok, 1000) {
        Ok(_) => Err("checkout verified under the payer's key"),
        Err(_) => Ok(()),
      },
    },
  }
}

fn run_all() -> Unit {
  let results := [happy_path(), lying_total_unsealable(), expired_checkout_rejected(), wrong_checkout_binding_rejected(), insufficient_ceiling_flagged(), wrong_signer_rejected()]
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

