use sample_rust::models::Product;
use sample_rust::Category;

fn main() {
    let book = Product::new("The Rust Book", 3_999, Category::Books);
    let price = book.total(2, true, Some("VIP10"));
    println!("{book}: {price}");
    let fallback = Product::default();
    println!("{fallback}");
}
