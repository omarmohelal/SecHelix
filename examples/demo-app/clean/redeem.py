"""Concurrency: the redemption is a single conditional write."""


def redeem(db, user_id, code):
    # The update only applies if the coupon is still unredeemed, and the row
    # count tells us whether this caller was the one that won the race.
    changed = db.execute(
        "UPDATE coupons SET redeemed = 1 WHERE code = ? AND redeemed = 0", [code]
    )
    if changed != 1:
        return {"error": "invalid coupon"}
    coupon = db.query("SELECT * FROM coupons WHERE code = ?", [code])
    db.execute(
        "INSERT INTO credits (user_id, amount, idempotency_key) VALUES (?, ?, ?)",
        [user_id, coupon["amount"], f"coupon:{code}"],
    )
    return {"credited": coupon["amount"]}
