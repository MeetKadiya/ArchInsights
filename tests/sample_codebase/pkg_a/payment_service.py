# tests/sample_codebase/pkg_a/payment_service.py
from .shipping_service import schedule_shipping


def process_payment(user_id, items):
    if not items:
        return False
    return schedule_shipping(user_id, items)
