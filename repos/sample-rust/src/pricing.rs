use crate::models::{Category, Priced, Product};

/// Deliberately tangled: expect a high-complexity finding.
pub fn quote(product: &Product, quantity: u32, member: bool, coupon: Option<&str>) -> u64 {
    let mut total = product.final_price(quantity, member);
    match product.category {
        Category::Food => {
            if quantity > 10 && member {
                total = total * 90 / 100;
            } else if quantity > 10 {
                total = total * 95 / 100;
            }
        }
        Category::Books => {
            if member || quantity > 3 {
                total -= 50;
            }
        }
        Category::Electronics => {
            for _ in 0..quantity {
                if total > 100_000 {
                    total -= 1_000;
                }
            }
        }
        Category::Other => {}
    }
    if let Some(code) = coupon {
        if code == "HALF" && total > 0 {
            total /= 2;
        } else if code.starts_with("VIP") || member {
            total -= total / 10;
        }
    }
    while total % 5 != 0 {
        total += 1;
    }
    total
}
