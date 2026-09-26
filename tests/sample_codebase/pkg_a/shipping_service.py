# tests/sample_codebase/pkg_a/shipping_service.py
from .order_service import OrderManager


def schedule_shipping(user_id, items):
    manager = OrderManager()
    return manager.audit_order(user_id)
