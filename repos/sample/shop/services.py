from shop.models import Product  # models imports services too -> circular import
from shop.pricing import apply_discount


def notify_change(product: Product) -> str:
    return f"{product.name} changed"


def checkout(product: Product, code: str | None = None, member: bool = False) -> float:
    return apply_discount(product.price, code, member)
