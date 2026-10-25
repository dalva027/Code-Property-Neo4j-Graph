use std::fmt;

use crate::pricing::quote;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Category {
    Food,
    Books,
    Electronics,
    Other,
}

#[derive(Debug, Clone)]
pub struct Product {
    pub name: String,
    pub price_cents: u64,
    pub category: Category,
}

pub trait Priced: fmt::Display {
    fn base_price(&self) -> u64;

    fn final_price(&self, quantity: u32, member: bool) -> u64 {
        self.base_price() * quantity as u64 - if member { 100 } else { 0 }
    }
}

impl Product {
    pub fn new(name: &str, price_cents: u64, category: Category) -> Self {
        Product { name: name.to_string(), price_cents, category }
    }

    pub fn total(&self, quantity: u32, member: bool, coupon: Option<&str>) -> u64 {
        quote(self, quantity, member, coupon)
    }
}

impl Priced for Product {
    fn base_price(&self) -> u64 {
        self.price_cents
    }
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} cents)", self.name, self.base_price())
    }
}

impl Default for Product {
    fn default() -> Self {
        Self::new("unnamed", 0, Category::Other)
    }
}
