use std::sync::Arc;
use std::{error::Error, path::Path};

use crate::ib::loader::*;
use funty::Unsigned;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use rapimt_core::action::ib::IbActionType;

#[derive(Parser)]
#[grammar = "src/ib/cmd_parser/ibfar.pest"]
struct IbFarParser;

#[derive(Debug, Default)]
pub struct FwdState {
    pub switch_guid: Guid,
    pub group_table: Vec<GroupSpec>,
    pub lft_table: Vec<LftEntry>,
}

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

/// [Rule::group_entry]
fn parse_group_entry(pair: Pair<'_, Rule>) -> GroupSpec {
    let mut group = GroupSpec::default();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::group_idx => {
                group.group_idx = parse_dec_ident(p);
            }
            Rule::ports => {
                if let Some(ports) = get_cache().get(p.as_str()) {
                    group.ports = ports.clone();
                } else {
                    let mut new_ports: Vec<PortIdx> = vec![];
                    let key = p.as_str().to_string();
                    for p1 in p.into_inner() {
                        new_ports.push(parse_dec_ident(p1));
                    }
                    let new_ports = Arc::new(new_ports);
                    get_mut_cache().insert(key, new_ports.clone());
                    group.ports = new_ports;
                }
            }
            _ => {}
        }
    }
    group
}

/// [Rule::group_def]
fn parse_group_def(pair: Pair<'_, Rule>) -> Vec<GroupSpec> {
    let mut group_table = Vec::new();
    for p in pair.into_inner() {
        if p.as_rule() == Rule::group_entry {
            group_table.push(parse_group_entry(p))
        }
    }
    group_table
}

/// [Rule::lft_entry]
fn parse_lft_entry(pair: Pair<'_, Rule>) -> LftEntry {
    let mut lft_entry = LftEntry::default();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::lid => lft_entry.lid = parse_hex_ident(p),
            Rule::static_port => lft_entry.port = parse_dec_ident(p),
            Rule::lid_state => {
                lft_entry.lid_state = match p.as_str() {
                    "Static" => IbActionType::Static,
                    "HBF" => IbActionType::HashBasedForwarding,
                    "Free" => IbActionType::AdaptiveRouting,
                    _ => unreachable!(),
                }
            }
            Rule::group => lft_entry.group = parse_dec_ident(p),
            _ => {}
        }
    }
    lft_entry
}

/// [Rule::lft_def]
fn parse_lft_def(pair: Pair<'_, Rule>) -> Vec<LftEntry> {
    let mut lft_table = Vec::new();
    for p in pair.into_inner() {
        if p.as_rule() == Rule::lft_entry {
            lft_table.push(parse_lft_entry(p))
        }
    }
    lft_table
}

/// [Rule::fwd_state]
fn parse_fwd_state(pair: Pair<'_, Rule>) -> FwdState {
    let mut state = FwdState::default();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::switch_stat => {
                state.switch_guid = parse_hex_ident(p.into_inner().next().unwrap())
            }
            Rule::group_def => state.group_table = parse_group_def(p),
            Rule::lft_def => state.lft_table = parse_lft_def(p),
            _ => {}
        }
    }
    state
}

/// [Rule::far_file]
fn parse_far_file(pair: Pair<'_, Rule>) -> Vec<FwdState> {
    let mut switches: Vec<FwdState> = Vec::new();
    for p in pair.into_inner() {
        if p.as_rule() == Rule::fwd_state {
            switches.push(parse_fwd_state(p))
        }
    }
    switches
}

/// Load forwarding states from .far file.
pub fn load_forwarding_tables(file: impl AsRef<Path>) -> Result<Vec<FwdState>, Box<dyn Error>> {
    let unparsed_file = std::fs::read_to_string(file)?;
    let file = IbFarParser::parse(Rule::far_file, &unparsed_file)
        .expect("unsuccessful parse") // unwrap the parse result
        .next()
        .unwrap();
    Ok(parse_far_file(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "file too big, this mod is also deprecated"]
    fn test_ibfar_parser() {
        let switches = load_forwarding_tables("examples/ibdiagnet2/ibdiagnet2.far").unwrap();

        println!("number of Switches: {}", switches.len());
        // println!("Cache size: {}", get_cache().len());
        // for k in get_cache().keys() {
        //     println!("Port group pattern: {}", k);
        // }
    }
}
