use std::error::Error;

use fxhash::FxHashMap;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use petgraph::algo::all_simple_paths;
use regex::bytes::RegexSetBuilder;

use super::{VeriReport, VerificationPlugin};

#[derive(IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
enum NodeTopoType {
    #[default]
    Host = b'H',
    LeafSwitch = b'L',
    SpineSwitch = b'S',
    CoreSwitch = b'C',
    VirtualNode = b'V',
}

pub fn label_node_topo_type(node_desc: &str) -> u8 {
    let t = if node_desc.contains("-ZS-") || node_desc.contains("-UFM-") {
        // UFM is also a host
        NodeTopoType::Host
    } else if node_desc.contains("-JR-") {
        NodeTopoType::LeafSwitch
    } else if node_desc.contains("-HJ-") {
        NodeTopoType::SpineSwitch
    } else if node_desc.contains("-HX-") {
        NodeTopoType::CoreSwitch
    } else {
        NodeTopoType::VirtualNode
    };
    t.into()
}

/// Require that all simple path have to match exactly one of regex in a regex set.
pub struct SimplePathExactRegexSetPlugin {
    name: String,
    pattern_count: Vec<(String, usize)>,
}

impl SimplePathExactRegexSetPlugin {
    pub fn new<II, S>(name: &str, patterns: II) -> Self
    where
        II: IntoIterator<Item = (S, usize)>,
        S: AsRef<str>,
    {
        Self {
            name: name.to_string(),
            pattern_count: patterns
                .into_iter()
                .map(|(s, c)| (s.as_ref().to_string(), c))
                .collect(),
        }
    }
}

impl VerificationPlugin for SimplePathExactRegexSetPlugin {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn execute(&self, cgraph: &mut super::CachedFwdGraph) -> Result<VeriReport, Box<dyn Error>> {
        // build exact regex set with ^$ anchors
        let regex_set =
            RegexSetBuilder::new(self.pattern_count.iter().map(|(s, _)| format!("^{}$", s)))
                .build()?;
        let g = &cgraph.graph;
        // we only verify graphs that have at least one host
        let dsts: Vec<_> = g
            .node_indices()
            .filter(|i| g[*i].label == NodeTopoType::Host.into())
            .collect();
        if dsts.is_empty() {
            return Ok("INFO: No host found in the graph, skip it.".into());
        }
        // pattern count
        let mut count_map = FxHashMap::default();
        for dst in dsts {
            for src in g.node_indices() {
                if src == dst || g[src].label != NodeTopoType::LeafSwitch.into() {
                    continue;
                }
                for path in all_simple_paths::<Vec<_>, _>(g, src, dst, 0, None) {
                    let mut symbols = Vec::new();
                    for node in path {
                        symbols.push(g[node].label);
                    }
                    for pattern_idx in regex_set.matches(&symbols) {
                        *count_map.entry(pattern_idx).or_insert(0usize) += 1;
                    }
                }
            }
        }
        let mut string_builder = String::from("INFO: ");
        for (idx, count) in count_map {
            string_builder.push_str(&regex_set.patterns()[idx]);
            string_builder.push_str(format!(": {} ", count).as_str());
        }
        Ok(string_builder)
    }

    fn review(&self, _report: &VeriReport) -> Result<bool, Box<dyn Error>> {
        todo!()
    }
}
