//! Small function bodies for the data-flow tests (backend/tests/test_code_facts.py): each `pub fn`
//! moves the value of `source()` towards `sink()` through one language construct. Analyzed by the
//! extractor into ../flows.code-facts.json; never built.
use std::process::Command;

pub fn source() -> String {
    std::env::args().nth(1).unwrap_or_default()
}

fn sink(command: &str) {
    let _ = Command::new(command).status();
}

pub fn let_chain() {
    let a = source();
    let b = a;
    let c = b;
    sink(&c);
}

pub fn method_chain() {
    let a = source();
    sink(a.trim().to_lowercase().as_str());
}

pub fn through_format() {
    let a = source();
    let line = format!("run {a} now");
    sink(&line);
}

pub fn through_format_args() {
    let a = source();
    let line = format!("run {} now", a);
    sink(&line);
}

pub fn through_try() -> Result<(), std::num::ParseIntError> {
    let a = source();
    let count: u32 = a.parse()?;
    sink(&count.to_string());
    Ok(())
}

struct Job {
    name: String,
    retries: u32,
}

pub fn struct_literal() -> u32 {
    let a = source();
    let job = Job { name: a, retries: 3 };
    sink(&job.name);
    job.retries
}

pub fn closure_param() {
    let a = source();
    let parts: Vec<String> = a.split(' ').map(|part| part.to_uppercase()).collect();
    for part in parts {
        sink(&part);
    }
}

fn pass_one(value: String) -> String {
    value
}

fn pass_two(value: String) -> String {
    pass_one(value)
}

pub fn one_call() {
    sink(&pass_one(source()));
}

pub fn two_calls() {
    sink(&pass_two(source()));
}

pub trait Runner {
    fn run(&self, command: &str);
}

pub struct Shell;

impl Runner for Shell {
    fn run(&self, command: &str) {
        sink(command);
    }
}

pub fn dispatch(runner: &dyn Runner) {
    runner.run(&source());
}

pub fn out_param() {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    sink(&line);
}

macro_rules! run {
    ($command:expr) => {
        sink($command)
    };
}

pub fn through_macro() {
    let a = source();
    run!(&a);
}

pub fn guarded() {
    let a = source();
    if a.starts_with("safe-") {
        sink(&a);
    }
}

pub fn untainted() {
    sink("ls");
}
