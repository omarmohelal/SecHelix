"""Concurrency: check and update are separate, so the coupon redeems twice."""


def redeem(db, user_id, code):
    coupon = db.query("SELECT * FROM coupons WHERE code = ?", [code])
    if not coupon or coupon["redeemed"]:
        return {"error": "invalid coupon"}
    # Two concurrent requests both observe redeemed=False before either write
    # lands, so both proceed and the discount is applied twice.
    db.execute("UPDATE coupons SET redeemed = 1 WHERE code = ?", [code])
    db.execute("INSERT INTO credits (user_id, amount) VALUES (?, ?)",
               [user_id, coupon["amount"]])
    return {"credited": coupon["amount"]}
