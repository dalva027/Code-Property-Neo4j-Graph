def apply_discount(price: float, code: str | None = None, member: bool = False) -> float:
    """Deliberately tangled so the complexity rule has something to flag."""
    if code is None and not member:
        return price
    if code == "HALF":
        price = price / 2
    elif code == "TEN":
        price = price * 0.9
    elif code == "FLAT5":
        price = price - 5 if price > 5 else 0
    elif code and code.startswith("VIP"):
        if member:
            price = price * 0.7
        else:
            price = price * 0.85
    if member:
        if price > 100:
            price = price - 10
        elif price > 50:
            price = price - 5
    return round(price, 2) if price > 0 else 0.0
