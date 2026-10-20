from shop.services import notify_change


class Product:
    def __init__(self, name: str, price: float):
        self.name = name
        self.price = price

    def rename(self, name: str) -> None:
        self.name = name
        notify_change(self)


class DigitalProduct(Product):
    def download_url(self) -> str:
        return f"/downloads/{self.name}"
