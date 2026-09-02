"""Business logic: the refund cannot exceed the remaining refundable total."""


def refund(payments, order_id, amount):
    order = payments.get_order(order_id)
    if order["status"] != "PAID":
        return {"error": "not refundable"}
    already = payments.refunded_total(order_id)
    remaining = order["captured_total"] - already
    if amount <= 0 or amount > remaining:
        return {"error": "amount exceeds refundable total"}
    payments.credit(order["user_id"], amount, idempotency_key=f"refund:{order_id}:{already}")
    return {"refunded": amount}
