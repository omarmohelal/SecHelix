"""Object authorization: the owner check is missing."""


def get_order(db, session, order_id):
    # The order is looked up by id alone. Any authenticated user who can guess
    # or enumerate an id receives another user's order.
    order = db.query("SELECT * FROM orders WHERE id = ?", [order_id])
    if not order:
        return None, 404
    return order, 200
