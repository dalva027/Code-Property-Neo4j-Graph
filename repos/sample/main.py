from shop.models import DigitalProduct
from shop.services import checkout


def main() -> None:
    book = DigitalProduct("graph-theory", 42.0)
    book.rename("graph-theory-2e")
    print(checkout(book, code="VIP1", member=True))


if __name__ == "__main__":
    main()
