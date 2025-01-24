use std::sync::Arc;

use fxhash::FxHashMap;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use petgraph::algo::all_simple_paths;
use rapimt_io::ib::loader::{Guid, LinkSpec};
use regex::bytes::{RegexSet, RegexSetBuilder};

use super::CachedFwdGraph;
use super::{IbPluginReport, PluginExecutorLike};

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
    name: Arc<str>,
    pattern_count: Vec<(String, usize)>,
    regex_set: RegexSet,
}

impl SimplePathExactRegexSetPlugin {
    pub fn new<II, S>(name: &str, patterns: II) -> Self
    where
        II: IntoIterator<Item = (S, usize)>,
        S: AsRef<str>,
    {
        let pattern_count: Vec<_> = patterns
            .into_iter()
            .map(|(s, c)| (s.as_ref().to_string(), c))
            .collect();
        let regex_set = RegexSetBuilder::new(pattern_count.iter().map(|(s, _)| format!("^{}$", s)))
            .build()
            .unwrap();
        Self {
            name: name.into(),
            pattern_count,
            regex_set,
        }
    }
}

impl PluginExecutorLike<IbPluginReport> for SimplePathExactRegexSetPlugin {
    type NID = Guid;
    type Edge = Arc<LinkSpec>;

    fn get_name(&self) -> Arc<str> {
        self.name.clone()
    }

    fn _execute(&self, cgraph: &mut CachedFwdGraph<Self::NID, Self::Edge, IbPluginReport>) {
        // we clone the regexset, the recommended way.
        // (https://docs.rs/regex/latest/regex/index.html#sharing-a-regex-across-threads-can-result-in-contention)
        let regex_set = self.regex_set.clone();
        let g = &cgraph.graph;
        // we only verify graphs that have at least one host
        let dsts: Vec<_> = g
            .node_indices()
            .filter(|i| g[*i].label == NodeTopoType::Host.into())
            .collect();
        if dsts.is_empty() {
            cgraph.report_cache.insert(
                self.get_name(),
                IbPluginReport {
                    to_lid: None,
                    to_guid: None,
                    should_report: false,
                    report: Ok("INFO: No host found in the graph, skip it.".into()),
                },
            );
            return;
        } else if dsts.len() > 1 {
            cgraph.report_cache.insert(
                self.get_name(),
                IbPluginReport {
                    to_lid: None,
                    to_guid: None,
                    should_report: false,
                    report: Err("ERROR: More than one host found in the graph.".into()),
                },
            );
            return;
        }
        // pattern count
        let mut count_map = FxHashMap::default();
        let dst = dsts[0];
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
        let mut string_builder = String::new();
        let mut mismatch = false;
        for (idx, count) in count_map {
            if count != self.pattern_count[idx].1 {
                mismatch = true;
            }
            string_builder.push_str(&regex_set.patterns()[idx]);
            string_builder.push_str(format!(": {} ", count).as_str());
        }
        if mismatch {
            cgraph.report_cache.insert(
                self.get_name(),
                IbPluginReport {
                    to_lid: Some(g[dst].lid),
                    to_guid: Some(g[dst].node_guid),
                    should_report: true,
                    report: Ok(format!("ERROR: {}", string_builder)),
                },
            );
        } else {
            cgraph.report_cache.insert(
                self.get_name(),
                IbPluginReport {
                    to_lid: Some(g[dst].lid),
                    to_guid: Some(g[dst].node_guid),
                    should_report: false,
                    report: Ok(format!("INFO: {}", string_builder)),
                },
            );
        }
    }
}
