# Mandate — AP2 (Agent Payments Protocol) Checkout and Payment mandates as
# signed JWTs (https://ap2-protocol.org/ap2/specification/).
#
# The flow this module models:
#
#   1. The MERCHANT seals a CheckoutMandate — the cart: line items, total,
#      currency, expiry. `verify_checkout` re-derives the total from the line
#      items, so a sealed total that doesn't match its own items never verifies.
#   2. The PAYER seals a PaymentMandate whose `checkout_hash` is the SHA-256 of
#      the *checkout token string it accepts* — the binding that makes the
#      payment authorization unambiguous about what it pays for. `max_cents`
#      caps the spend.
#   3. Settlement verifies both tokens (each under its signer's key), the hash
#      binding, both expiries, and that `max_cents` covers the total
#      (`payment_covers`).
#
# Money is integer cents throughout — never floats in a budget. Clock reads
# stay at the caller's edge: verification takes `now` (unix seconds) as an
# argument and stays pure.

import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.list" as list

import "std.json" as json

import "./jwa" as jwa

import "./jwt" as jwt

# One cart line. `unit_cents` is the per-unit price in integer cents.
type LineItem = { sku :: Str, description :: Str, qty :: Int, unit_cents :: Int }

# The merchant's half: what is being bought, for how much, until when.
type CheckoutMandate = { merchant_id :: Str, items :: List[LineItem], total_cents :: Int, currency :: Str, expires_at :: Int }

# The payer's half: which checkout (by token hash), which instrument, the
# spend ceiling, until when.
type PaymentMandate = { checkout_hash :: Str, instrument_id :: Str, max_cents :: Int, expires_at :: Int }

# ── Pure arithmetic / binding helpers ────────────────────────────────────────
fn items_total_cents(items :: List[LineItem]) -> Int
  examples {
    items_total_cents([]) => 0,
    items_total_cents([{ sku: "a", description: "one", qty: 2, unit_cents: 150 }, { sku: "b", description: "two", qty: 1, unit_cents: 99 }]) => 399
  }
{
  list.fold(items, 0, fn (acc :: Int, it :: LineItem) -> Int {
    acc + it.qty * it.unit_cents
  })
}

# base64url(SHA-256(checkout token string)) — the payment→checkout binding.
fn checkout_hash(checkout_token :: Str) -> Str
  examples {
    checkout_hash("checkout-token") => "9zuQRNCjnbgodsolYOxiI078c-JWBom1taP8kvcJBOM"
  }
{
  crypto.base64url_encode(crypto.sha256(bytes.from_str(checkout_token)))
}

# Does the payment's ceiling cover the checkout's total?
fn payment_covers(p :: PaymentMandate, c :: CheckoutMandate) -> Bool
  examples {
    payment_covers({ checkout_hash: "h", instrument_id: "card-1", max_cents: 500, expires_at: 10 }, { merchant_id: "m", items: [], total_cents: 399, currency: "EUR", expires_at: 10 }) => true,
    payment_covers({ checkout_hash: "h", instrument_id: "card-1", max_cents: 398, expires_at: 10 }, { merchant_id: "m", items: [], total_cents: 399, currency: "EUR", expires_at: 10 }) => false
  }
{
  p.max_cents >= c.total_cents
}

# ── Sealing (signing) ────────────────────────────────────────────────────────
# Sign a CheckoutMandate. Refuses a mandate whose declared total doesn't match
# its own line items — a lie should not be signable through this API.
# Deterministic; token vectors live in tests/test_mandate.lex.
fn seal_checkout(alg :: jwa.Alg, key :: Bytes, m :: CheckoutMandate) -> Result[Str, Str] {
  if m.total_cents == items_total_cents(m.items) {
    jwt.encode(alg, key, json.stringify(m))
  } else {
    Err("total_cents does not match the line items")
  }
}

# Build the payer's mandate against the literal checkout token it accepts.
fn make_payment(checkout_token :: Str, instrument_id :: Str, max_cents :: Int, expires_at :: Int) -> PaymentMandate {
  { checkout_hash: checkout_hash(checkout_token), instrument_id: instrument_id, max_cents: max_cents, expires_at: expires_at }
}

# Sign a PaymentMandate. Deterministic; vectors live in tests/test_mandate.lex.
fn seal_payment(alg :: jwa.Alg, key :: Bytes, m :: PaymentMandate) -> Result[Str, Str] {
  jwt.encode(alg, key, json.stringify(m))
}

# ── Verification ─────────────────────────────────────────────────────────────
# Verify a checkout token under the MERCHANT's key: signature + header alg,
# required fields, not expired at `now`, and the total re-derived from the
# line items. Returns the mandate on success.
fn verify_checkout(alg :: jwa.Alg, key :: Bytes, token :: Str, now :: Int) -> Result[CheckoutMandate, Str] {
  match jwt.decode(alg, key, token) {
    Err(e) => Err(e),
    Ok(payload) => match (json.parse_strict(payload, ["merchant_id", "items", "total_cents", "currency", "expires_at"]) :: Result[CheckoutMandate, Str]) {
      Err(e) => Err(str.concat("not a checkout mandate: ", e)),
      Ok(m) => if m.expires_at > now {
        if m.total_cents == items_total_cents(m.items) {
          Ok(m)
        } else {
          Err("total_cents does not match the line items")
        }
      } else {
        Err("checkout mandate expired")
      },
    },
  }
}

# Verify a payment token under the PAYER's key, bound to a specific checkout
# token: signature + header alg, required fields, not expired at `now`, and
# `checkout_hash` must equal the hash of the checkout token presented here.
# Whether the ceiling covers the total is a separate, explicit question —
# `payment_covers` — because settlement may legitimately check it against an
# amended total.
fn verify_payment(alg :: jwa.Alg, key :: Bytes, token :: Str, checkout_token :: Str, now :: Int) -> Result[PaymentMandate, Str] {
  match jwt.decode(alg, key, token) {
    Err(e) => Err(e),
    Ok(payload) => match (json.parse_strict(payload, ["checkout_hash", "instrument_id", "max_cents", "expires_at"]) :: Result[PaymentMandate, Str]) {
      Err(e) => Err(str.concat("not a payment mandate: ", e)),
      Ok(m) => if m.expires_at > now {
        if m.checkout_hash == checkout_hash(checkout_token) {
          Ok(m)
        } else {
          Err("payment mandate is bound to a different checkout")
        }
      } else {
        Err("payment mandate expired")
      },
    },
  }
}

