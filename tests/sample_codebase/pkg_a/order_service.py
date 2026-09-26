# tests/sample_codebase/pkg_a/order_service.py
from .payment_service import process_payment
from ..pkg_b.user_service import get_user


class OrderManager:
    """Deliberate God Class with excessive methods and branching."""

    def __init__(self):
        self.orders = []

    def create_order(self, user_id, items):
        if not user_id:
            raise ValueError("User ID required")
        if len(items) == 0:
            raise ValueError("No items in order")
        return process_payment(user_id, items)

    def validate_inventory(self, items):
        for item in items:
            if item.get('qty', 0) <= 0:
                return False
        return True

    def calculate_tax(self, total, state):
        if state == "NY":
            return total * 0.08
        elif state == "CA":
            return total * 0.095
        elif state == "TX":
            return total * 0.0625
        return total * 0.05

    def apply_discount(self, total, code):
        if code == "SUMMER" and total > 100:
            return total * 0.8
        elif code == "VIP" or code == "LOYALTY":
            return total * 0.85
        return total

    def process_refund(self, order_id):
        if not order_id:
            return False
        return True

    def send_invoice(self, order_id):
        return f"Invoice sent for {order_id}"

    def audit_order(self, order_id):
        return f"Audited {order_id}"

    def archive_order(self, order_id):
        return True

    def generate_receipt(self, order_id):
        return f"Receipt-{order_id}"
