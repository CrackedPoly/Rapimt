use std::sync::Arc;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use petgraph::graph::{DiGraph, NodeIndex};
use rapimt_io::ib::loader::{Guid, LinkSpec, NodeCommon};
use regex::bytes::{RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{
    plugin::{AnyGraphPlugin, GraphPluginLike},
    AnyReport, ReportLike,
};

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

#[derive(Snafu, Serialize, Deserialize, Clone, Debug)]
enum GraphException {
    #[snafu(display("More than one destination found in the graph"))]
    MoreThanOneDst,
    #[snafu(display("Destination is not a host"))]
    DstIsNotHost,
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
#[derive(Debug)]
pub struct SimplePathExactRegexSetPlugin {
    name: Arc<str>,
    enabled: bool,
    regex_set: RegexSet,
    expected_count: Arc<[(Arc<str>, usize)]>,
    actual_count: Vec<usize>,
    dst: Option<Guid>,
    exception: Option<GraphException>,
}

impl SimplePathExactRegexSetPlugin {
    pub fn new<II, S>(name: &str, patterns: II) -> Self
    where
        II: IntoIterator<Item = (S, usize)>,
        S: AsRef<str>,
    {
        let expected_count: Vec<_> = patterns
            .into_iter()
            .map(|(s, c)| (s.as_ref().into(), c))
            .collect();
        let len = expected_count.len();
        let regex_set =
            RegexSetBuilder::new(expected_count.iter().map(|(s, _)| format!("^{}$", s)))
                .build()
                .unwrap();
        Self {
            name: name.into(),
            enabled: true,
            regex_set,
            expected_count: expected_count.into(),
            actual_count: vec![0usize; len],
            dst: None,
            exception: None,
        }
    }

    pub fn should_report(&self) -> bool {
        // WARN: we now do not consider exceptions, but sometimes this indicates a problem
        if self.exception.is_some() {
            return false;
        }
        let mut mismatch = false;
        for (idx, count) in self.actual_count.iter().enumerate() {
            if *count != self.expected_count[idx].1 {
                mismatch = true;
            }
        }
        mismatch
    }
}

impl GraphPluginLike<Guid, Arc<NodeCommon>, Arc<LinkSpec>> for SimplePathExactRegexSetPlugin {
    fn get_name(&self) -> Arc<str> {
        self.name.clone()
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn clone_boxed(&self) -> AnyGraphPlugin<Guid, Arc<NodeCommon>, Arc<LinkSpec>> {
        Box::new(Self {
            name: self.name.clone(),
            enabled: self.enabled,
            regex_set: self.regex_set.clone(),
            expected_count: self.expected_count.clone(),
            actual_count: vec![0usize; self.expected_count.len()],
            dst: None,
            exception: None,
        })
    }

    fn recognize_path(
        &mut self,
        graph: &DiGraph<Arc<NodeCommon>, Arc<LinkSpec>>,
        path: &[NodeIndex],
    ) {
        // if exception has been raised, skip the path
        if self.exception.is_some() {
            return;
        }
        // check if all paths have the same destination
        let last = path[path.len() - 1];
        if let Some(dst) = self.dst {
            if graph[last].node_guid != dst {
                self.exception = Some(GraphException::MoreThanOneDst);
                return;
            }
        } else {
            self.dst = Some(graph[last].node_guid);
        }
        // check if the destination is a host
        if graph[last].label != NodeTopoType::Host.into() {
            self.exception = Some(GraphException::DstIsNotHost);
            return;
        }
        // concatenating the symbols
        let mut symbols = Vec::new();
        for node in path {
            symbols.push(graph[*node].label);
        }
        // increment corresponding pattern count
        for pattern_idx in self.regex_set.matches(&symbols) {
            self.actual_count[pattern_idx] += 1;
        }
    }

    fn report(&self) -> AnyReport {
        match self.exception {
            None => Box::new(RegexSetReport {
                to_guid: self.dst,
                should_report: self.should_report(),
                report: Ok(self
                    .actual_count
                    .iter()
                    .enumerate()
                    .map(|(idx, count)| (self.expected_count[idx].0.clone(), *count))
                    .collect()),
            }),
            Some(GraphException::MoreThanOneDst) => Box::new(RegexSetReport {
                to_guid: self.dst,
                should_report: false,
                report: Err(GraphException::MoreThanOneDst),
            }),
            Some(GraphException::DstIsNotHost) => Box::new(RegexSetReport {
                to_guid: self.dst,
                should_report: false,
                report: Err(GraphException::DstIsNotHost),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexSetReport {
    to_guid: Option<Guid>,
    should_report: bool,
    report: Result<Vec<(Arc<str>, usize)>, GraphException>,
}

#[typetag::serde]
impl ReportLike for RegexSetReport {
    fn should_report(&self) -> bool {
        self.should_report
    }
}
