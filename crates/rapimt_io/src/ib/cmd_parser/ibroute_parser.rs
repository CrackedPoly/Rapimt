use std::{error::Error, path::Path};

use funty::Unsigned;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

use crate::prelude::{Guid, RawIbFibRule};

#[derive(Parser)]
#[grammar = "src/ib/cmd_parser/ibroute.pest"]
struct IbRouteParser;

/// [Rule::hex_bare_ident]
fn parse_hex_bare_ident<U: Unsigned>(pair: Pair<'_, Rule>) -> U {
    let hex_bare_ident = match pair.as_rule() {
        Rule::hex_bare_ident => pair,
        _ => pair
            .into_inner()
            .find(|p| p.as_rule() == Rule::hex_bare_ident)
            .unwrap(),
    };
    U::from_str_radix(hex_bare_ident.as_str(), 16).unwrap()
}

/// [Rule::hex_ident]
fn parse_hex_ident<U: Unsigned>(pair: Pair<'_, Rule>) -> U {
    let hex_ident = match pair.as_rule() {
        Rule::hex_ident => pair,
        _ => pair
            .into_inner()
            .find(|p| p.as_rule() == Rule::hex_ident)
            .unwrap(),
    };
    parse_hex_bare_ident(hex_ident)
}

/// [Rule::digit_ident]
fn parse_dec_ident<U: Unsigned>(pair: Pair<'_, Rule>) -> U {
    let digit_ident = match pair.as_rule() {
        Rule::digit_ident => pair,
        _ => pair
            .into_inner()
            .find(|p| p.as_rule() == Rule::digit_ident)
            .unwrap(),
    };
    U::from_str_radix(digit_ident.as_str(), 10).unwrap()
}

/// [Rule::fib_rule]
fn parse_fib_rule(pair: Pair<'_, Rule>) -> RawIbFibRule {
    let mut rule = RawIbFibRule::default();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::hex_ident => rule.lid = parse_hex_ident(p),
            Rule::digit_ident => rule.port = parse_dec_ident(p),
            Rule::parenthesed => {
                rule.description = p.as_str()[1..p.as_str().len() - 1].to_string()
            }
            _ => {}
        }
    }
    rule
}

/// Load LFT from ibroute output.
pub fn load_routes(file: impl AsRef<Path>) -> Result<(Guid, Vec<RawIbFibRule>), Box<dyn Error>> {
    let file_name = file
        .as_ref()
        .file_name()
        .ok_or("File path should not terminates with . or ..")?
        .to_str()
        .ok_or("Invalid UTF-8 file name")?;
    let guid = Guid::from_str_radix(&file_name[2..], 16)?;
    let unparsed_file = std::fs::read_to_string(file)?;
    let file = IbRouteParser::parse(Rule::fib_file, &unparsed_file)?
        .next()
        .unwrap();
    let mut fib_rules = Vec::new();
    for rule in file.into_inner() {
        match rule.as_rule() {
            Rule::fib_file_heading_unicast => {}
            Rule::fib_header => {}
            Rule::fib_rule => fib_rules.push(parse_fib_rule(rule)),
            Rule::fib_conclusion => {}
            Rule::EOI => {}
            _ => {}
        }
    }
    Ok((guid, fib_rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, fs};

    #[test]
    #[ignore = "too many files, this mod is also deprecated"]
    fn test_ibroute_parser() {
        let mut switches = HashMap::new();
        for file in fs::read_dir("examples/ibroute/").unwrap() {
            let (file_name, fib_rules) = load_routes(file.unwrap().path()).unwrap();
            switches.insert(file_name, fib_rules);
        }
        println!("number of Switches: {}", switches.len());
        let (mut max, mut min) = (0usize, usize::MAX);
        for (_, v) in switches.iter() {
            max = max.max(v.len());
            min = min.min(v.len());
        }
        println!("max #rules: {}, min #rules: {}", max, min);
    }
}
