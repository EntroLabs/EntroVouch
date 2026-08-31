"""Fixture module: pure computation, no egress. The negative case matters as
much as the positive one — an auditor that flags everything is unusable."""
from decimal import Decimal


def line_total(unit_price: Decimal, quantity: int, discount_bp: int = 0) -> Decimal:
    if quantity < 0:
        raise ValueError("quantity must not be negative")
    gross = unit_price * quantity
    return gross - (gross * Decimal(discount_bp) / Decimal(10_000))


def invoice_total(lines) -> Decimal:
    return sum((line_total(*l) for l in lines), Decimal("0"))
