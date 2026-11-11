//! A recursive-descent parser for nested parentheses with no depth limit.
use std::iter::Peekable;
use std::str::Chars;

pub enum Node {
    Leaf,
    List(Vec<Node>),
}

impl Node {
    /// Recursive over the tree it was built from; deep input means a deep stack.
    pub fn depth(&self) -> usize {
        match self {
            Node::Leaf => 1,
            Node::List(items) => 1 + items.iter().map(|n| n.depth()).max().unwrap_or(0),
        }
    }
}

pub fn parse(input: &str) -> Node {
    let mut chars = input.chars().peekable();
    parse_list(&mut chars)
}

fn parse_list(chars: &mut Peekable<Chars<'_>>) -> Node {
    let mut items = Vec::new();
    while let Some(c) = chars.next() {
        match c {
            '(' => items.push(parse_item(chars)),
            ')' => break,
            _ => items.push(Node::Leaf),
        }
    }
    Node::List(items)
}

fn parse_item(chars: &mut Peekable<Chars<'_>>) -> Node {
    parse_list(chars)
}

/// Bounded recursion: the depth parameter guards it, so it is not reported.
pub fn count_nested(s: &str, depth: usize) -> usize {
    if depth > 64 || s.is_empty() {
        return depth;
    }
    count_nested(&s[1..], depth + 1)
}
