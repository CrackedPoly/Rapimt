use std::{
    borrow::Borrow,
    cell::RefCell,
    collections::HashSet,
    fmt::{Binary, Debug},
    hash::Hash,
    iter::Extend,
    rc::Rc,
};

use crate::segment::{Segment, Segmentized};

#[cfg(feature = "graphviz")]
use graphviz_rust::{
    cmd::{CommandArg, Format},
    exec, parse,
    printer::PrinterContext,
};
#[cfg(feature = "graphviz")]
use std::fmt::Display;

#[allow(dead_code)]
trait Handle {}

impl<V> Handle for HashSet<V> {}

struct TreeNode<V> {
    cond: Segment,
    depth: usize,
    values: HashSet<V>,
    subsets: HashSet<V>,
    lch: Option<TreeNodeRef<V>>,
    rch: Option<TreeNodeRef<V>>,
    wch: Option<TreeNodeRef<V>>,
}

type TreeNodeRef<V> = Rc<RefCell<TreeNode<V>>>;

// this is a helper trait for bypassing the external struct constraint
trait TNode<V> {
    fn recursive_dump(&self, depth: usize);
    fn new(
        cond: Segment,
        depth: usize,
        value: HashSet<V>,
        lch: Option<TreeNodeRef<V>>,
        rch: Option<TreeNodeRef<V>>,
        wch: Option<TreeNodeRef<V>>,
    ) -> Self;
}

impl<V> TNode<V> for TreeNodeRef<V>
where
    V: Eq + Hash + Clone + Debug,
{
    fn recursive_dump(&self, depth: usize) {
        let cond_str = format!("{}{:b}", "-".repeat(depth), self.as_ref().borrow().cond);
        let value_str = if self.as_ref().borrow().values.is_empty() {
            String::from(" -- Local: None")
        } else {
            format!(" -- Local: {:?}", self.as_ref().borrow().values)
        };
        let subset_str = if self.as_ref().borrow().subsets.is_empty() {
            String::from(" -- Subsets: None")
        } else {
            format!(" -- Subsets: {:?}", self.as_ref().borrow().subsets)
        };
        println!("{cond_str} {value_str} {subset_str}");
        if let Some(lch) = &self.as_ref().borrow().lch {
            lch.recursive_dump(depth + self.as_ref().borrow().cond.len);
        }
        if let Some(rch) = &self.as_ref().borrow().rch {
            rch.recursive_dump(depth + self.as_ref().borrow().cond.len);
        }
        if let Some(wch) = &self.as_ref().borrow().wch {
            wch.recursive_dump(depth + self.as_ref().borrow().cond.len);
        }
    }

    fn new(
        cond: Segment,
        depth: usize,
        value: HashSet<V>,
        lch: Option<TreeNodeRef<V>>,
        rch: Option<TreeNodeRef<V>>,
        wch: Option<TreeNodeRef<V>>,
    ) -> Self {
        let mut node = TreeNode {
            cond,
            depth,
            values: value,
            subsets: HashSet::new(),
            lch,
            rch,
            wch,
        };
        node.subsets.extend(node.values.clone());
        if let Some(lch) = &node.lch {
            node.subsets.extend(lch.as_ref().borrow().subsets.clone());
        }
        if let Some(rch) = &node.rch {
            node.subsets.extend(rch.as_ref().borrow().subsets.clone());
        }
        if let Some(wch) = &node.wch {
            node.subsets.extend(wch.as_ref().borrow().subsets.clone());
        }
        Rc::new(RefCell::new(node))
    }
}

pub struct TernaryPatriciaTree<V> {
    root: Option<TreeNodeRef<V>>,
    max_depth: usize,
}

impl<V> TernaryPatriciaTree<V>
where
    V: Eq + Hash + Clone + Debug,
{
    #[inline]
    pub fn new(max_depth: usize) -> Self {
        TernaryPatriciaTree {
            root: None,
            max_depth,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.root = None;
    }

    #[inline]
    pub fn all(&self) -> HashSet<V> {
        if let Some(node) = &self.root {
            node.as_ref().borrow().subsets.clone()
        } else {
            HashSet::new()
        }
    }

    fn insert_rec<S>(
        &self,
        node_ref: Option<TreeNodeRef<V>>,
        value: V,
        segmentized: &mut S,
        depth: usize,
    ) -> Option<TreeNodeRef<V>>
    where
        S: Segmentized<V>,
    {
        if depth > self.max_depth {
            return None;
        }
        if node_ref.is_none() {
            // Tree is empty, create a new node
            while segmentized.has_next() {
                segmentized.proceed(1);
            }
            return Some(<TreeNodeRef<V> as TNode<V>>::new(
                segmentized.current(),
                depth,
                HashSet::from([value.clone()]),
                None,
                None,
                None,
            ));
        }
        let node = node_ref.unwrap();
        let lpm = segmentized.lpm(node.as_ref().borrow().cond);
        let final_node = if node.as_ref().borrow().cond.len == lpm.len {
            // the patricia have the node that prefixed the segment
            node
        } else {
            // or we need to split the node to create another branch
            self.split_node(node, lpm)
        };
        final_node
            .as_ref()
            .borrow_mut()
            .subsets
            .insert(value.clone());
        if !segmentized.has_next() || self.node_is_last(&final_node) {
            final_node
                .as_ref()
                .borrow_mut()
                .values
                .insert(value.clone());
            return Some(final_node);
        }
        let wseg = segmentized.assert_next(false, false);
        let lseg = segmentized.assert_next(false, true);
        let rseg = segmentized.assert_next(true, true);
        let mut r_mut = final_node.as_ref().borrow_mut();

        if let Some(mut wseg) = wseg {
            r_mut.wch = self.insert_rec(
                r_mut.borrow().wch.clone(),
                value.clone(),
                &mut wseg,
                depth + r_mut.borrow().cond.len,
            );
        } else if let Some(mut lseg) = lseg {
            r_mut.lch = self.insert_rec(
                r_mut.borrow().lch.clone(),
                value.clone(),
                &mut lseg,
                depth + r_mut.borrow().cond.len,
            )
        } else if let Some(mut rseg) = rseg {
            r_mut.rch = self.insert_rec(
                r_mut.borrow().rch.clone(),
                value.clone(),
                &mut rseg,
                depth + r_mut.borrow().cond.len,
            )
        }
        Some(final_node.clone())
    }

    #[inline]
    pub fn insert<S>(&mut self, value: V, mut segmentized: S)
    where
        S: Segmentized<V>,
    {
        self.root = self.insert_rec(self.root.clone(), value, &mut segmentized, 0)
    }

    fn search_rec<S>(
        &self,
        node_ref: Option<TreeNodeRef<V>>,
        value: V,
        segmentized: &mut S,
    ) -> HashSet<V>
    where
        S: Segmentized<V> + Binary,
    {
        if node_ref.is_none() {
            return HashSet::new();
        }
        let node = node_ref.unwrap();
        let cond = node.as_ref().borrow().cond;
        segmentized.proceed(cond.len);
        let curr_seg = segmentized.current();
        if cond.intersect_any(curr_seg) {
            if !segmentized.has_next() || self.node_is_leaf(&node) {
                return node.as_ref().borrow().subsets.clone();
            }
            let nset = &node.as_ref().borrow().values;

            let wseger = segmentized.cut();
            let wset = if let Some(mut wseger) = wseger {
                self.search_rec(
                    node.as_ref().borrow().wch.clone(),
                    value.clone(),
                    &mut wseger,
                )
            } else {
                HashSet::new()
            };

            let lseger = segmentized.assert_next(false, true);
            let lset = if let Some(mut lseger) = lseger {
                self.search_rec(
                    node.as_ref().borrow().lch.clone(),
                    value.clone(),
                    &mut lseger,
                )
            } else {
                HashSet::new()
            };

            let rseger = segmentized.assert_next(true, true);
            let rset = if let Some(mut rseger) = rseger {
                self.search_rec(
                    node.as_ref().borrow().rch.clone(),
                    value.clone(),
                    &mut rseger,
                )
            } else {
                HashSet::new()
            };

            match segmentized.next_pair() {
                (false, false) => &(&(&wset | &lset) | &rset) | nset,
                (false, true) => &(&wset | &lset) | nset,
                _ => &(&wset | &rset) | nset,
            }
        } else {
            HashSet::new()
        }
    }

    #[inline]
    pub fn search<S>(&self, value: V, mut segmentized: S) -> HashSet<V>
    where
        S: Segmentized<V> + Binary,
    {
        self.search_rec(self.root.clone(), value, &mut segmentized)
    }

    fn delete_rec<S>(
        &self,
        node_ref: Option<TreeNodeRef<V>>,
        value: V,
        segmentized: &mut S,
    ) -> Option<TreeNodeRef<V>>
    where
        S: Segmentized<V>,
    {
        if node_ref.is_none() {
            return node_ref;
        }
        let node = node_ref.unwrap();
        segmentized.proceed(node.as_ref().borrow().cond.len);
        if node.as_ref().borrow().cond != segmentized.current() {
            // the structure is not right, so the value is not in the tree
            return Some(node);
        }
        node.as_ref().borrow_mut().subsets.remove(&value);
        if !segmentized.has_next() || self.node_is_last(&node) {
            node.as_ref().borrow_mut().values.remove(&value);
        }
        let wseg = segmentized.assert_next(false, false);
        let lseg = segmentized.assert_next(false, true);
        let rseg = segmentized.assert_next(true, true);
        {
            let mut r_mut = node.as_ref().borrow_mut();
            if let Some(mut wseg) = wseg {
                r_mut.wch = self.delete_rec(r_mut.borrow().wch.clone(), value.clone(), &mut wseg);
            } else if let Some(mut lseg) = lseg {
                r_mut.lch = self.delete_rec(r_mut.borrow().lch.clone(), value.clone(), &mut lseg)
            } else if let Some(mut rseg) = rseg {
                r_mut.rch = self.delete_rec(r_mut.borrow().rch.clone(), value.clone(), &mut rseg)
            }
        }
        self.compact_node(node)
    }

    #[inline]
    pub fn delete<S>(&mut self, value: V, mut segmentized: S)
    where
        S: Segmentized<V>,
    {
        self.root = self.delete_rec(self.root.clone(), value, &mut segmentized)
    }

    fn split_node(&self, node: TreeNodeRef<V>, segment: Segment) -> TreeNodeRef<V> {
        // we should create a new node that points to the node
        let offset = segment.len;
        let depth = node.as_ref().borrow().depth;
        // modify the old node
        node.as_ref().borrow_mut().depth += offset;
        node.as_ref().borrow_mut().cond.shift_left(offset);
        let seg = node.as_ref().borrow().cond;
        match (seg.mv.value[0], seg.mv.mask[0]) {
            (false, false) => <TreeNodeRef<V> as TNode<V>>::new(
                segment,
                depth,
                HashSet::new(),
                None,
                None,
                Some(node),
            ),
            (false, true) => <TreeNodeRef<V> as TNode<V>>::new(
                segment,
                depth,
                HashSet::new(),
                Some(node),
                None,
                None,
            ),
            _ => <TreeNodeRef<V> as TNode<V>>::new(
                segment,
                depth,
                HashSet::new(),
                None,
                Some(node),
                None,
            ),
        }
    }

    fn compact_node(&self, node: TreeNodeRef<V>) -> Option<TreeNodeRef<V>> {
        let n_ref = node.as_ref().borrow();
        if n_ref.subsets.is_empty() {
            None
        } else if n_ref.values.is_empty() {
            let only_ch = match (
                n_ref.lch.is_some(),
                n_ref.rch.is_some(),
                n_ref.wch.is_some(),
            ) {
                (true, false, false) => n_ref.lch.clone(),
                (false, true, false) => n_ref.rch.clone(),
                (false, false, true) => n_ref.wch.clone(),
                _ => None,
            };
            if let Some(ch) = only_ch {
                ch.as_ref().borrow_mut().cond.prepend(n_ref.cond);
                ch.as_ref().borrow_mut().depth = n_ref.depth;
                return Some(ch);
            } else {
                return Some(node.clone());
            }
        } else {
            return Some(node.clone());
        }
    }

    #[inline]
    fn node_is_leaf(&self, node: &TreeNodeRef<V>) -> bool {
        let r = node.as_ref().borrow();
        r.lch.is_none() && r.rch.is_none() && r.wch.is_none()
    }

    #[inline]
    fn node_is_last(&self, node: &TreeNodeRef<V>) -> bool {
        let r = node.as_ref().borrow();
        r.depth + r.cond.len >= self.max_depth
    }

    #[inline]
    #[allow(dead_code)]
    fn dump(&self) {
        if let Some(node) = &self.root {
            node.recursive_dump(0);
        }
    }
}

#[cfg(feature = "graphviz")]
#[allow(dead_code)]
pub trait GraphvizDebug {
    fn visualize(&self, filename: &str);
}

#[cfg(feature = "graphviz")]
impl<V> GraphvizDebug for TernaryPatriciaTree<V>
where
    V: Display,
{
    fn visualize(&self, filename: &str) {
        fn inner_rec<V: Display>(
            node_ref: TreeNodeRef<V>,
            depth: usize,
        ) -> Option<(String, String)> {
            let node = node_ref.as_ref().borrow();
            let w_graph = if let Some(wch) = &node.wch {
                inner_rec(wch.clone(), depth + node.cond.len)
            } else {
                None
            };
            let l_graph = if let Some(lch) = &node.lch {
                inner_rec(lch.clone(), depth + node.cond.len)
            } else {
                None
            };
            let r_graph = if let Some(rch) = &node.rch {
                inner_rec(rch.clone(), depth + node.cond.len)
            } else {
                None
            };
            let cond_str = format!("{:b}", node.cond);
            let cond_str = cond_str[..node.cond.len].to_string();
            let cond_str_escaped = cond_str.replace('*', "x");
            let node_id = format!("node_{}_{}", depth, cond_str_escaped);
            let mut graph = format!(
                r#"{node_id} [label="{{cond: {cond_str} | values: {values} | subsets: {subsets}}}"];
                "#,
                node_id = node_id,
                cond_str = cond_str,
                values = node
                    .values
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(", "),
                subsets = node
                    .subsets
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(", "),
            );
            if let Some((l_id, l_graph)) = l_graph {
                let l_edge = format!(
                    r#"{node_id} -> {l_id} [label="0"];
                    "#,
                );
                graph.push_str(&l_edge);
                graph.push_str(&l_graph);
            }
            if let Some((w_id, w_graph)) = w_graph {
                let w_edge = format!(
                    r#"{node_id} -> {w_id} [label="*"];
                    "#,
                );
                graph.push_str(&w_edge);
                graph.push_str(&w_graph);
            }
            if let Some((r_id, r_graph)) = r_graph {
                let r_edge = format!(
                    r#"{node_id} -> {r_id} [label="1"];
                    "#,
                );
                graph.push_str(&r_edge);
                graph.push_str(&r_graph);
            }
            Some((node_id, graph))
        }

        let graph_str = if let Some(node) = &self.root {
            let (_, graph) = inner_rec(node.clone(), 0).unwrap();
            Some(format!(
                r#"digraph TernaryPatriciaTree {{
                node [shape=record];
                {}
            }}"#,
                graph
            ))
        } else {
            None
        };
        if let Some(graph_str) = graph_str {
            let g = parse(&graph_str).expect("Wrong graphviz format");
            let _ = exec(
                g,
                &mut PrinterContext::default(),
                vec![
                    Format::Pdf.into(),
                    CommandArg::Output(String::from(filename)),
                ],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{tests::from_str, Segmentizer};

    #[test]
    fn test_tpt_insert_search() {
        let mut tpt = TernaryPatriciaTree::<&str> {
            root: None,
            max_depth: 32,
        };
        let str0 = "**";
        let str1 = "*****";
        let str2 = "0*1**";
        let str3 = "***1*";
        let str4 = "**11*";
        let str5 = "**00";
        let segmentizer = |s| Segmentizer::from(from_str(s));
        tpt.insert(str0, segmentizer(str0));
        tpt.insert(str1, segmentizer(str1));
        assert_eq!(
            tpt.search(str2, segmentizer(str2)),
            HashSet::from(["**", "*****"])
        );
        tpt.insert(str2, segmentizer(str2));
        assert_eq!(
            tpt.search(str3, segmentizer(str3)),
            HashSet::from(["**", "*****", "0*1**"])
        );
        tpt.insert(str3, segmentizer(str3));
        assert_eq!(
            tpt.search(str4, segmentizer(str4)),
            HashSet::from(["**", "*****", "0*1**", "***1*"])
        );
        tpt.insert(str4, segmentizer(str4));
        assert_eq!(
            tpt.search(str5, segmentizer(str5)),
            HashSet::from(["**", "*****"])
        );
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_insert_search.pdf");
    }

    #[test]
    fn test_tpt_delete() {
        let mut tpt = TernaryPatriciaTree::<&str> {
            root: None,
            max_depth: 32,
        };
        let str0 = "**";
        let str1 = "*****";
        let str2 = "0*1**";
        let str3 = "***1*";
        let str4 = "**11*";
        let segmentizer = |s| Segmentizer::from(from_str(s));
        tpt.insert(str0, segmentizer(str0));
        tpt.insert(str1, segmentizer(str1));
        tpt.insert(str2, segmentizer(str2));
        tpt.insert(str3, segmentizer(str3));
        tpt.insert(str4, segmentizer(str4));
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_delete0.pdf");

        tpt.delete(str4, segmentizer(str4));
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_delete1.pdf");

        tpt.delete(str0, segmentizer(str0));
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_delete2.pdf");

        let remains = tpt.search("*", segmentizer("*"));
        assert_eq!(remains.len(), 3);
    }
}
