//! Tiny terminal UI helpers: colour (only on a TTY) and boxed reports.

use std::io::IsTerminal;

fn color_on() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

pub fn paint(s: &str, code: &str) -> String {
    if color_on() {
        format!("\x1b[{}m{}\x1b[0m", code, s)
    } else {
        s.to_string()
    }
}

pub const GREEN: &str = "32";
pub const RED: &str = "31";
pub const YELLOW: &str = "33";
pub const DIM: &str = "2";

pub enum Row {
    Line(String, Option<&'static str>),
    Sep,
}

pub fn line(s: impl Into<String>) -> Row {
    Row::Line(s.into(), None)
}

pub fn colored(s: impl Into<String>, code: &'static str) -> Row {
    Row::Line(s.into(), Some(code))
}

/// Print rows inside a box with a title in the top border.
pub fn boxed(title: &str, rows: &[Row]) {
    let inner = rows
        .iter()
        .filter_map(|r| match r {
            Row::Line(s, _) => Some(s.chars().count()),
            Row::Sep => None,
        })
        .max()
        .unwrap_or(0)
        .max(title.chars().count() + 4)
        .max(44);
    let w = inner + 2;
    let fill = w - (title.chars().count() + 3);
    println!("┌─ {} {}┐", title, "─".repeat(fill));
    for r in rows {
        match r {
            Row::Sep => println!("├{}┤", "─".repeat(w)),
            Row::Line(s, c) => {
                let padded = format!("{:<width$}", s, width = inner);
                let shown = match c {
                    Some(code) => paint(&padded, code),
                    None => padded,
                };
                println!("│ {} │", shown);
            }
        }
    }
    println!("└{}┘", "─".repeat(w));
}
