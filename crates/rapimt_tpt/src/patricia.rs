use std::{
    cell::UnsafeCell,
    collections::{BTreeSet, HashSet},
    fmt::{Binary, Debug},
    hash::{Hash, RandomState},
    iter::Extend,
    ops::BitOr,
    ptr::NonNull,
};

use crate::segment::{Segment, Segmentized};

use fxhash::FxHashSet;
#[cfg(feature = "graphviz")]
use graphviz_rust::{
    cmd::{CommandArg, Format},
    exec, parse,
    printer::PrinterContext,
};
#[cfg(feature = "graphviz")]
use std::fmt::Display;

pub trait Value: Ord + Eq + Hash + Clone {}

impl<V: Ord + Eq + Hash + Clone> Value for V {}

pub trait SetHandle<V: Value>: Default + Clone + Extend<V> + IntoIterator<Item = V> {
    fn is_empty(&self) -> bool;

    fn new(value: V) -> Self {
        let mut h = Self::default();
        h.extend(Some(value));
        h
    }

    fn clear(&mut self);

    fn remove(&mut self, value: &V) -> bool;

    fn insert(&mut self, value: V) -> bool;

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a;
}

impl<V: Value> SetHandle<V> for FxHashSet<V> {
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn clear(&mut self) {
        self.clear()
    }

    fn remove(&mut self, value: &V) -> bool {
        self.remove(value)
    }

    fn insert(&mut self, value: V) -> bool {
        self.insert(value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a,
    {
        self.iter()
    }
}

impl<V: Value> SetHandle<V> for HashSet<V, RandomState> {
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn clear(&mut self) {
        self.clear()
    }

    fn remove(&mut self, value: &V) -> bool {
        self.remove(value)
    }

    fn insert(&mut self, value: V) -> bool {
        self.insert(value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a,
    {
        self.iter()
    }
}

impl<V: Value> SetHandle<V> for BTreeSet<V> {
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn clear(&mut self) {
        self.clear()
    }

    fn remove(&mut self, value: &V) -> bool {
        self.remove(value)
    }

    fn insert(&mut self, value: V) -> bool {
        self.insert(value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a,
    {
        self.iter()
    }
}

struct TreeNode<V: Value, H: SetHandle<V>> {
    cond: Segment,
    depth: usize,
    values: H,
    subsets: H,
    // search_handle is used to store the search result in the TPT search process to avoid unnecessary
    // memory allocation and deallocation.
    search_handle: H,
    lch: Option<TreeNodePtr<V, H>>,
    rch: Option<TreeNodePtr<V, H>>,
    wch: Option<TreeNodePtr<V, H>>,

    _marker: std::marker::PhantomData<V>,
}

type TreeNodePtr<V, H> = NonNull<TreeNode<V, H>>;

macro_rules! box_drop {
    ($e:expr) => {
        let _ = Box::from_raw($e.as_ptr());
    };
}

impl<V: Value, H: SetHandle<V>> Drop for TreeNode<V, H> {
    fn drop(&mut self) {
        unsafe {
            if let Some(lch) = &self.lch {
                box_drop!(lch);
            }
            if let Some(rch) = &self.rch {
                box_drop!(rch);
            }
            if let Some(wch) = &self.wch {
                box_drop!(wch);
            }
        }
    }
}

// this is a helper trait for bypassing the external struct constraint
trait TNode<V: Value, H: SetHandle<V>> {
    fn recursive_dump(&self, depth: usize);
    fn new(
        cond: Segment,
        depth: usize,
        value: H,
        lch: Option<TreeNodePtr<V, H>>,
        rch: Option<TreeNodePtr<V, H>>,
        wch: Option<TreeNodePtr<V, H>>,
    ) -> Self;
}

impl<V, H> TNode<V, H> for TreeNodePtr<V, H>
where
    V: Value + Debug,
    H: SetHandle<V> + Debug,
{
    fn recursive_dump(&self, depth: usize) {
        unsafe {
            let cond_str = format!("{}{:b}", "-".repeat(depth), self.as_ref().cond);
            let value_str = if self.as_ref().values.is_empty() {
                String::from(" -- Local: None")
            } else {
                format!(" -- Local: {:?}", self.as_ref().values)
            };
            let subset_str = if self.as_ref().subsets.is_empty() {
                String::from(" -- Subsets: None")
            } else {
                format!(" -- Subsets: {:?}", self.as_ref().subsets)
            };
            println!("{cond_str} {value_str} {subset_str}");
            if let Some(lch) = &self.as_ref().lch {
                lch.recursive_dump(depth + self.as_ref().cond.len);
            }
            if let Some(rch) = &self.as_ref().rch {
                rch.recursive_dump(depth + self.as_ref().cond.len);
            }
            if let Some(wch) = &self.as_ref().wch {
                wch.recursive_dump(depth + self.as_ref().cond.len);
            }
        }
    }

    fn new(
        cond: Segment,
        depth: usize,
        value: H,
        lch: Option<TreeNodePtr<V, H>>,
        rch: Option<TreeNodePtr<V, H>>,
        wch: Option<TreeNodePtr<V, H>>,
    ) -> Self {
        let mut node = Box::new(TreeNode {
            cond,
            depth,
            values: value,
            subsets: H::default(),
            search_handle: H::default(),
            lch,
            rch,
            wch,
            _marker: std::marker::PhantomData,
        });
        node.subsets.extend(node.values.clone());
        unsafe {
            if let Some(lch) = &node.lch {
                node.subsets.extend(lch.as_ref().subsets.clone());
            }
            if let Some(rch) = &node.rch {
                node.subsets.extend(rch.as_ref().subsets.clone());
            }
            if let Some(wch) = &node.wch {
                node.subsets.extend(wch.as_ref().subsets.clone());
            }
        }
        NonNull::new(Box::into_raw(node)).unwrap()
    }
}

pub struct TernaryPatriciaTree<V: Value, H: SetHandle<V>> {
    root: Option<TreeNodePtr<V, H>>,
    max_depth: usize,
    empty: UnsafeCell<H>,
}

impl<V, H> TernaryPatriciaTree<V, H>
where
    V: Value + Debug,
    H: SetHandle<V> + Debug,
    for<'a> &'a H: BitOr<Output = H>,
{
    #[inline]
    pub fn new(max_depth: usize) -> Self {
        TernaryPatriciaTree {
            root: None,
            max_depth,
            empty: UnsafeCell::new(H::default()),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        unsafe {
            if let Some(node) = &self.root {
                box_drop!(node);
            }
            self.root = None;
            (*self.empty.get()).clear();
        }
    }

    #[inline]
    pub fn all(&self) -> &H {
        unsafe {
            if let Some(node) = &self.root {
                &node.as_ref().subsets
            } else {
                (*self.empty.get()).clear();
                &*self.empty.get()
            }
        }
    }

    #[inline]
    pub fn insert<S>(&mut self, value: V, mut segmentized: S)
    where
        S: Segmentized<V>,
    {
        unsafe { self.root = self.insert_rec(self.root, value, &mut segmentized, 0) }
    }

    unsafe fn insert_rec<S>(
        &self,
        node_ptr: Option<TreeNodePtr<V, H>>,
        value: V,
        segmentized: &mut S,
        depth: usize,
    ) -> Option<TreeNodePtr<V, H>>
    where
        S: Segmentized<V>,
    {
        if depth > self.max_depth {
            return None;
        }
        if node_ptr.is_none() {
            // Tree is empty, create a new node
            while segmentized.has_next() {
                segmentized.proceed(1);
            }
            return Some(<TreeNodePtr<V, H> as TNode<V, H>>::new(
                segmentized.current(),
                depth,
                H::new(value.clone()),
                None,
                None,
                None,
            ));
        }

        let node = node_ptr.unwrap();
        let node_ref = node.as_ref();
        let lpm = segmentized.lpm(node_ref.cond);

        let mut final_node = if node_ref.cond.len == lpm.len {
            // the patricia have the node that prefixed the segment
            node
        } else {
            // or we need to split the node to create another branch
            self.split_node(node, lpm)
        };
        final_node.as_mut().subsets.insert(value.clone());
        if !segmentized.has_next() || self.node_is_last(&final_node) {
            final_node.as_mut().values.insert(value.clone());
            return Some(final_node);
        }

        let f_mut = final_node.as_mut();
        if let Some(mut wseg) = segmentized.assert_next(false, false) {
            f_mut.wch = self.insert_rec(f_mut.wch, value.clone(), &mut wseg, depth + f_mut.cond.len)
        } else if let Some(mut lseg) = segmentized.assert_next(false, true) {
            f_mut.lch = self.insert_rec(f_mut.lch, value.clone(), &mut lseg, depth + f_mut.cond.len)
        } else if let Some(mut rseg) = segmentized.assert_next(true, true) {
            f_mut.rch = self.insert_rec(f_mut.rch, value.clone(), &mut rseg, depth + f_mut.cond.len)
        }
        Some(final_node)
    }

    #[inline]
    pub fn search<S>(&self, mut segmentized: S) -> &H
    where
        S: Segmentized<V> + Binary,
    {
        unsafe {
            if self.root.is_none() {
                return &(*self.empty.get());
            }
            self.search_rec(self.root, &mut segmentized);
            &self.root.unwrap().as_ref().search_handle
        }
    }

    unsafe fn search_rec<S>(&self, node_ptr: Option<TreeNodePtr<V, H>>, segmentized: &mut S)
    where
        S: Segmentized<V> + Binary,
    {
        if node_ptr.is_none() {
            return;
        }
        let mut node = node_ptr.unwrap();
        let node_mut = node.as_mut();
        let cond = node_mut.cond;
        segmentized.proceed(cond.len);
        let curr_seg = segmentized.current();

        if cond.intersect_any(curr_seg) {
            // clear search result
            node_mut.search_handle.clear();

            // this segment intersect with all the subsets
            if !segmentized.has_next() || self.node_is_leaf(&node) {
                node_mut
                    .search_handle
                    .extend(node_mut.subsets.iter().cloned());
                return;
            }

            // or at leaset it intersect with the local values and wildcard branch search results
            node_mut
                .search_handle
                .extend(node_mut.values.iter().cloned());
            let wseger = segmentized.cut();
            if let Some(mut wseger) = wseger {
                if let Some(wch) = node_mut.wch {
                    self.search_rec(Some(wch), &mut wseger);
                    node_mut
                        .search_handle
                        .extend(wch.as_ref().search_handle.iter().cloned());
                }
            }

            match segmentized.next_pair() {
                (false, true) => {
                    let lseger = segmentized.assert_next(false, true);
                    if let Some(mut lseger) = lseger {
                        if let Some(lch) = node_mut.lch {
                            self.search_rec(Some(lch), &mut lseger);
                            node_mut
                                .search_handle
                                .extend(lch.as_ref().search_handle.iter().cloned());
                        }
                    }
                }
                (true, true) => {
                    let rseger = segmentized.assert_next(true, true);
                    if let Some(mut rseger) = rseger {
                        if let Some(rch) = node_mut.rch {
                            self.search_rec(Some(rch), &mut rseger);
                            node_mut
                                .search_handle
                                .extend(rch.as_ref().search_handle.iter().cloned());
                        }
                    }
                }
                // (false, false) or (true, false)
                _ => {
                    let lseger = segmentized.assert_next(false, true);
                    if let Some(mut lseger) = lseger {
                        if let Some(lch) = node_mut.lch {
                            self.search_rec(Some(lch), &mut lseger);
                            node_mut
                                .search_handle
                                .extend(lch.as_ref().search_handle.iter().cloned());
                        }
                    }
                    let rseger = segmentized.assert_next(true, true);
                    if let Some(mut rseger) = rseger {
                        if let Some(rch) = node_mut.rch {
                            self.search_rec(Some(rch), &mut rseger);
                            node_mut
                                .search_handle
                                .extend(rch.as_ref().search_handle.iter().cloned());
                        }
                    }
                }
            }
        } else {
            node_mut.search_handle.clear();
        }
    }

    #[inline]
    pub fn delete<S>(&mut self, value: &V, mut segmentized: S)
    where
        S: Segmentized<V>,
    {
        unsafe { self.root = self.delete_rec(self.root, value, &mut segmentized) }
    }

    unsafe fn delete_rec<S>(
        &self,
        node_ptr: Option<TreeNodePtr<V, H>>,
        value: &V,
        segmentized: &mut S,
    ) -> Option<TreeNodePtr<V, H>>
    where
        S: Segmentized<V>,
    {
        if node_ptr.is_none() {
            return node_ptr;
        }
        let mut node = node_ptr.unwrap();
        let node_mut = node.as_mut();
        segmentized.proceed(node_mut.cond.len);
        if node_mut.cond != segmentized.current() {
            // the structure is not right, so the value is not in the tree
            return Some(node);
        }
        node_mut.subsets.remove(value);
        if !segmentized.has_next() || self.node_is_last(&node) {
            node_mut.values.remove(value);
        }

        if let Some(mut wseg) = segmentized.assert_next(false, false) {
            node_mut.wch = self.delete_rec(node_mut.wch, value, &mut wseg)
        } else if let Some(mut lseg) = segmentized.assert_next(false, true) {
            node_mut.lch = self.delete_rec(node_mut.lch, value, &mut lseg)
        } else if let Some(mut rseg) = segmentized.assert_next(true, true) {
            node_mut.rch = self.delete_rec(node_mut.rch, value, &mut rseg)
        }
        self.compact_node(node)
    }

    // Create a new node that points to the node
    unsafe fn split_node(
        &self,
        mut node: TreeNodePtr<V, H>,
        segment: Segment,
    ) -> TreeNodePtr<V, H> {
        // we should create a new node that points to the node
        let offset = segment.len;
        let depth = node.as_ref().depth;
        // modify the old node
        node.as_mut().depth += offset;
        node.as_mut().cond.shift_left(offset);
        let seg = node.as_ref().cond;
        match (seg.mv.value[0], seg.mv.mask[0]) {
            (false, false) => <TreeNodePtr<V, H> as TNode<V, H>>::new(
                segment,
                depth,
                H::default(),
                None,
                None,
                Some(node),
            ),
            (false, true) => <TreeNodePtr<V, H> as TNode<V, H>>::new(
                segment,
                depth,
                H::default(),
                Some(node),
                None,
                None,
            ),
            _ => <TreeNodePtr<V, H> as TNode<V, H>>::new(
                segment,
                depth,
                H::default(),
                None,
                Some(node),
                None,
            ),
        }
    }

    unsafe fn compact_node(&self, mut node: TreeNodePtr<V, H>) -> Option<TreeNodePtr<V, H>> {
        let n_ref = node.as_ref();
        if n_ref.subsets.is_empty() {
            box_drop!(node);
            None
        } else if n_ref.values.is_empty() {
            let only_ch = match (
                n_ref.lch.is_some(),
                n_ref.rch.is_some(),
                n_ref.wch.is_some(),
            ) {
                (true, false, false) => n_ref.lch,
                (false, true, false) => n_ref.rch,
                (false, false, true) => n_ref.wch,
                _ => None,
            };
            if let Some(mut ch) = only_ch {
                ch.as_mut().cond.prepend(n_ref.cond);
                ch.as_mut().depth = n_ref.depth;
                node.as_mut().lch = None;
                node.as_mut().rch = None;
                node.as_mut().wch = None;
                box_drop!(node);
                return Some(ch);
            } else {
                return Some(node);
            }
        } else {
            return Some(node);
        }
    }

    #[inline]
    unsafe fn node_is_leaf(&self, node: &TreeNodePtr<V, H>) -> bool {
        let r = node.as_ref();
        r.lch.is_none() && r.rch.is_none() && r.wch.is_none()
    }

    #[inline]
    unsafe fn node_is_last(&self, node: &TreeNodePtr<V, H>) -> bool {
        let r = node.as_ref();
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
pub trait GraphvizDebug {
    fn visualize(&self, filename: &str);
}

#[cfg(feature = "graphviz")]
impl<V, H> GraphvizDebug for TernaryPatriciaTree<V, H>
where
    V: Value + Display,
    H: SetHandle<V>,
{
    fn visualize(&self, filename: &str) {
        unsafe fn inner_rec<U: Value + Display, G: SetHandle<U>>(
            node_ptr: TreeNodePtr<U, G>,
            depth: usize,
        ) -> Option<(String, String)> {
            let node = node_ptr.as_ref();
            let w_graph = if let Some(wch) = &node.wch {
                inner_rec(*wch, depth + node.cond.len)
            } else {
                None
            };
            let l_graph = if let Some(lch) = &node.lch {
                inner_rec(*lch, depth + node.cond.len)
            } else {
                None
            };
            let r_graph = if let Some(rch) = &node.rch {
                inner_rec(*rch, depth + node.cond.len)
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
            let (_, graph) = unsafe { inner_rec(*node, 0).unwrap() };
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
        let mut tpt = TernaryPatriciaTree::<&str, HashSet<&str>>::new(32);
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
            tpt.search(segmentizer(str2)),
            &HashSet::from(["**", "*****"])
        );
        tpt.insert(str2, segmentizer(str2));
        assert_eq!(
            tpt.search(segmentizer(str3)),
            &HashSet::from(["**", "*****", "0*1**"])
        );
        tpt.insert(str3, segmentizer(str3));
        assert_eq!(
            tpt.search(segmentizer(str4)),
            &HashSet::from(["**", "*****", "0*1**", "***1*"])
        );
        tpt.insert(str4, segmentizer(str4));
        assert_eq!(
            tpt.search(segmentizer(str5)),
            &HashSet::from(["**", "*****"])
        );
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_insert_search.pdf");
    }

    #[test]
    fn test_tpt_delete() {
        let mut tpt = TernaryPatriciaTree::<&str, HashSet<&str>>::new(32);
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

        tpt.delete(&str4, segmentizer(str4));
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_delete1.pdf");

        tpt.delete(&str0, segmentizer(str0));
        #[cfg(feature = "graphviz")]
        tpt.visualize("debug/test_tpt_delete2.pdf");

        let remains = tpt.search(segmentizer("*"));
        assert_eq!(remains.len(), 3);

        tpt.clear();
        assert_eq!(tpt.all().len(), 0);
    }
}
