"""Object authorization: ownership is established before returning."""


def get_order(db, session, order_id):
    order = db.query("SELECT * FROM orders WHERE id = ?", [order_id])
    if not order:
        return None, 404
    # The object is only returned to the identity that owns it. A miss is 404
    # rather than 403 so the endpoint does not confirm the id exists.
    if order["user_id"] != session["user_id"]:
        return None, 404
    return order, 200
