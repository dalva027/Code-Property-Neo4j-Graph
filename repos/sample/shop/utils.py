import re


def slugify(name: str) -> str:
    """Nobody calls this: expect an unused-function finding."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def legacy_export(products: list) -> str:
    return "\n".join(p.name for p in products)
