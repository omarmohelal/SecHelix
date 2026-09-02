"""Business logic: the refund is not bounded by what was paid."""


def refund(payments, order_id, amount):
    order = payments.get_order(order_id)
    if order["status"] != "PAID":
        return {"error": "not refundable"}
    # `amount` is caller-supplied and never compared against the captured total
    # or against refunds already issued, so an order can be refunded repeatedly
    # and for more than it was worth.
    payments.credit(order["user_id"], amount)
    return {"refunded": amount}
