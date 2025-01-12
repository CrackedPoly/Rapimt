use std::borrow::Borrow;

use funty::Unsigned;
use num_enum::IntoPrimitive;
use pest::iterators::Pair;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "src/ib/ibtopo.pest"]
pub struct IbTopoParser;

pub trait NodeType {}

pub struct Switch {}
pub struct Ca {}

impl NodeType for Switch {}
impl NodeType for Ca {}

type Guid = u64;
type PortIdx = u8;
type Lid = u16;

/// Common topology information for all nodes (switch and ca).
#[derive(Default, Debug)]
pub struct NodeCommon {
    vendid: u16,
    devid: u16,
    sysimg_guid: Guid,
    node_guid: Guid,
    port_guid: Option<Guid>,
    port_num: PortIdx,
    description: Option<String>,
}

/// IB switch spec.
#[derive(Default, Debug)]
pub struct SwitchSpec {
    common: NodeCommon,

    base_port: PortIdx,
    port_lid: Lid,
    port_lmc: Lid,

    links: Vec<LinkSpec>,
}

/// IB channel adapter spec.
#[derive(Default, Debug)]
pub struct CaSpec {
    common: NodeCommon,

    links: Vec<LinkSpec>,
}

/// Speed unit of a port.
#[derive(IntoPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum SpeedUnit {
    #[default]
    SRD = 0,
    DDR = 1,
    QDR = 2,
    FDR = 3,
    EDR = 4,
    HDR = 5,
    NDR = 6,
}

impl<T: Borrow<str>> From<T> for SpeedUnit {
    fn from(s: T) -> Self {
        match s.borrow() {
            "SRD" => SpeedUnit::SRD,
            "DDR" => SpeedUnit::DDR,
            "QDR" => SpeedUnit::QDR,
            "FDR" => SpeedUnit::FDR,
            "EDR" => SpeedUnit::EDR,
            "HDR" => SpeedUnit::HDR,
            "NDR" => SpeedUnit::NDR,
            _ => SpeedUnit::SRD,
        }
    }
}

/// Link spec between two ports.
#[derive(Default, Debug)]
pub struct LinkSpec {
    src_port_idx: PortIdx,
    dst_port_idx: PortIdx,
    src_port_lid: Lid,
    dst_port_lid: Lid,
    widthspeed: u8,
    speed_unit: SpeedUnit,
    src_node_guid: Option<Guid>,
    dst_node_guid: Option<Guid>,
    description: Option<String>,
}

/// [Rule::hex_bare_ident]
fn parse_hex_bare_ident<U: Unsigned>(pair: Pair<'_, Rule>) -> U {
    let hex_bare_ident = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::hex_bare_ident)
        .unwrap();
    U::from_str_radix(hex_bare_ident.as_str(), 16).unwrap()
}

/// [Rule::hex_ident]
fn parse_hex_ident<U: Unsigned>(pair: Pair<'_, Rule>) -> U {
    let hex_ident = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::hex_ident)
        .unwrap();
    parse_hex_bare_ident(hex_ident)
}

/// [Rule::switchguid_stat]
fn parse_switch_guid(pair: Pair<'_, Rule>) -> (Guid, Option<Guid>) {
    let mut node_guid = 0;
    let mut port_guid = None;
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::node_hex_ident => node_guid = parse_hex_ident(p),
            Rule::port_hex_ident => port_guid = Some(parse_hex_bare_ident(p)),
            _ => {}
        }
    }
    (node_guid, port_guid)
}

/// [Rule::caguid_stat]
fn parse_ca_guid(pair: Pair<'_, Rule>) -> Guid {
    let ca_guid = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::node_hex_ident)
        .unwrap();
    parse_hex_ident(ca_guid)
}

/// [Rule::port_id], [Rule::port_num], [Rule::lid], [Rule::lmc]
fn parse_dec_ident<U: Unsigned>(pair: Pair<'_, Rule>) -> U {
    let digit_ident = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::digit_ident)
        .unwrap();
    U::from_str_radix(digit_ident.as_str(), 10).unwrap()
}

/// [Rule::src_port_id], [Rule::dst_port_id]
fn parse_port_id(pair: Pair<'_, Rule>) -> PortIdx {
    let port_id = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::port_id)
        .unwrap();
    parse_dec_ident(port_id)
}

/// [Rule::widthspeed]
fn parse_widthspeed(pair: Pair<'_, Rule>) -> (u8, SpeedUnit) {
    let mut width = 0u8;
    let mut unit = SpeedUnit::SRD;
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::port_width => width = parse_dec_ident(p),
            Rule::speedunit => unit = SpeedUnit::from(p.as_str()),
            _ => {}
        }
    }
    (width, unit)
}

/// [Rule::link_spec]
fn parse_link_spec(pair: Pair<'_, Rule>) -> LinkSpec {
    let mut spec = LinkSpec::default();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::src_port_id => spec.src_port_idx = parse_port_id(p),
            Rule::port_src_node_ident => spec.src_node_guid = Some(parse_hex_bare_ident(p)),
            Rule::dst_port_id => spec.dst_port_idx = parse_port_id(p),
            Rule::port_dst_node_ident => spec.dst_node_guid = Some(parse_hex_bare_ident(p)),
            Rule::desc => spec.description = Some(p.as_str().to_string()),
            Rule::lid => spec.dst_port_lid = parse_dec_ident(p),
            Rule::widthspeed => (spec.widthspeed, spec.speed_unit) = parse_widthspeed(p),
            _ => {}
        }
    }
    spec
}

/// [Rule::switch_meta]
pub fn parse_switch_meta(spec: &mut SwitchSpec, pair: Pair<'_, Rule>) {
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::port_num => spec.common.port_num = parse_dec_ident(p),
            Rule::node_name => { /* duplicate guid */ }
            Rule::desc => spec.common.description = Some(p.as_str().to_string()),
            Rule::base_port => spec.base_port = parse_dec_ident(p),
            Rule::lid => spec.port_lid = parse_dec_ident(p),
            Rule::lmc => spec.port_lmc = parse_dec_ident(p),
            _ => {}
        }
    }
}

/// [Rule::switch_spec]
pub fn parse_switch_spec(spec: &mut SwitchSpec, pair: Pair<'_, Rule>) {
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::vendid_stat => spec.common.vendid = parse_hex_ident(p),
            Rule::devid_stat => spec.common.devid = parse_hex_ident(p),
            Rule::sysimgguid_stat => spec.common.sysimg_guid = parse_hex_ident(p),
            Rule::switchguid_stat => {
                (spec.common.node_guid, spec.common.port_guid) = parse_switch_guid(p)
            }
            Rule::switch_meta => parse_switch_meta(spec, p),
            Rule::link_spec => spec.links.push(parse_link_spec(p)),
            _ => {}
        }
    }
    for link in spec.links.iter_mut() {
        link.src_port_lid = spec.port_lid;
    }
}

/// [Rule::ca_meta]
pub fn parse_ca_meta(spec: &mut CaSpec, pair: Pair<'_, Rule>) {
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::port_num => spec.common.port_num = parse_dec_ident(p),
            Rule::node_name => { /* duplicate guid */ }
            Rule::desc => spec.common.description = Some(p.as_str().to_string()),
            _ => {}
        }
    }
}

/// [Rule::ca_spec]
pub fn parse_ca_spec(spec: &mut CaSpec, pair: Pair<'_, Rule>) {
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::vendid_stat => spec.common.vendid = parse_hex_ident(p),
            Rule::devid_stat => spec.common.devid = parse_hex_ident(p),
            Rule::sysimgguid_stat => spec.common.sysimg_guid = parse_hex_ident(p),
            Rule::caguid_stat => spec.common.node_guid = parse_ca_guid(p),
            Rule::ca_meta => parse_ca_meta(spec, p),
            Rule::link_spec => spec.links.push(parse_link_spec(p)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pest::Parser;
    use std::fs;

    #[test]
    fn test_ibtopo_parser() {
        let mut switches: Vec<SwitchSpec> = Vec::new();
        let mut cas: Vec<CaSpec> = Vec::new();

        let unparsed_file =
            fs::read_to_string("examples/ibnetdiscover/topo.txt").expect("cannot read file");
        let file = IbTopoParser::parse(Rule::file, &unparsed_file)
            .expect("unsuccessful parse") // unwrap the parse result
            .next()
            .unwrap(); // get and unwrap the `file` rule; never fails
        for topo in file.into_inner() {
            match topo.as_rule() {
                Rule::heading_comment => {}
                Rule::switch_spec => {
                    let mut switch = SwitchSpec::default();
                    parse_switch_spec(&mut switch, topo);
                    switches.push(switch);
                }
                Rule::ca_spec => {
                    let mut ca = CaSpec::default();
                    parse_ca_spec(&mut ca, topo);
                    cas.push(ca);
                }
                Rule::EOI => {}
                _ => {}
            }
        }

        println!("number of Switches: {}", switches.len());
        println!("number of Cas: {}", cas.len());
        // dbg!(&switches);
        // dbg!(&cas);
    }
}
