use std::{
    cell::UnsafeCell,
    collections::{BTreeSet, BinaryHeap, HashMap},
    rc::Rc,
};

use fxhash::{FxBuildHasher, FxHashMap};
use rapimt_core::prelude::{
    constant, Action, Dimension, MaskedValue, MatchEncoder, Predicate, PredicateInner, Rule, Single,
};
use rapimt_tpt::prelude::{Segmentizer, TernaryPatriciaTree};

use crate::im::{InverseModel, InverseModelMonoid};

type RcRule<P, A> = Rc<Rule<P, A>>;

/// Storage of rules.
pub trait RuleStore<A: Action<Single>, P: PredicateInner>: Default {
    fn insert(&mut self, rule: RcRule<P, A>);
    fn delete(&mut self, rule: &RcRule<P, A>);
    fn clear(&mut self);
    /// Return a clonable, sorted, double-ended iterator of rules that MAY overlap with the given
    /// rule.
    fn search<'a, 'b>(
        &'a self,
        rule: &'b RcRule<P, A>,
    ) -> impl Clone + DoubleEndedIterator<Item = &'a RcRule<P, A>>
    where
        A: 'a,
        P: 'a;
}

pub struct TPTRuleStore<A, P>
where
    A: Action<Single>,
    P: PredicateInner,
{
    #[allow(clippy::type_complexity)]
    tpt: TernaryPatriciaTree<RcRule<P, A>, BTreeSet<RcRule<P, A>>>,
    search_handle: UnsafeCell<BTreeSet<RcRule<P, A>>>,
}

impl<A, P> Default for TPTRuleStore<A, P>
where
    A: Action<Single>,
    P: PredicateInner,
{
    fn default() -> Self {
        TPTRuleStore {
            tpt: TernaryPatriciaTree::new(constant::MAX_POS),
            search_handle: UnsafeCell::new(BTreeSet::new()),
        }
    }
}

impl<A, P> RuleStore<A, P> for TPTRuleStore<A, P>
where
    A: Action<Single>,
    P: PredicateInner,
{
    fn insert(&mut self, rule: RcRule<P, A>) {
        for mv in rule.origin.iter() {
            self.tpt.insert(rule.clone(), Segmentizer::from(*mv));
        }
    }

    fn delete(&mut self, rule: &RcRule<P, A>) {
        for mv in rule.origin.iter() {
            self.tpt.delete(rule, Segmentizer::from(*mv));
        }
    }

    fn clear(&mut self) {
        self.tpt.clear();
    }

    fn search<'a, 'b>(
        &'a self,
        rule: &'b RcRule<P, A>,
    ) -> impl Clone + DoubleEndedIterator<Item = &'a RcRule<P, A>>
    where
        A: 'a,
        P: 'a,
    {
        unsafe {
            let set = &mut *self.search_handle.get();
            set.clear();
            for mv in rule.origin.iter() {
                set.extend(self.tpt.search(Segmentizer::from(*mv)).clone())
            }
            (*set).iter()
        }
    }
}

pub struct SimpleRuleStore<A, P>
where
    A: Action<Single>,
    P: PredicateInner,
{
    rules: BTreeSet<RcRule<P, A>>,
}

impl<A, P> Default for SimpleRuleStore<A, P>
where
    A: Action<Single>,
    P: PredicateInner,
{
    fn default() -> Self {
        SimpleRuleStore {
            rules: BTreeSet::new(),
        }
    }
}

impl<A, P> RuleStore<A, P> for SimpleRuleStore<A, P>
where
    A: Action<Single>,
    P: PredicateInner,
{
    fn insert(&mut self, rule: RcRule<P, A>) {
        self.rules.insert(rule);
    }
    fn delete(&mut self, rule: &RcRule<P, A>) {
        self.rules.remove(rule);
    }
    fn clear(&mut self) {
        self.rules.clear();
    }
    fn search<'a, 'b>(
        &'a self,
        _rule: &'b RcRule<P, A>,
    ) -> impl Clone + DoubleEndedIterator<Item = &'a RcRule<P, A>>
    where
        A: 'a,
        P: 'a,
    {
        self.rules.iter()
    }
}

// Rule storage and IM generator.
pub trait RuleMonitor<A: Action<Single>, P: PredicateInner> {
    // Required methods
    fn clear(&mut self);

    // First call of update should return an inverse model of the current state.
    // Subsequent calls should return an inverse model in the form of incremental update.
    fn update<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, P, T>>(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<P, A>>,
        deletion: impl IntoIterator<Item = Rule<P, A>>,
    ) -> InverseModel<OA, P, T, M>;

    // Provided methods
    fn insert<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, P, T>>(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<P, A>>,
    ) -> InverseModel<OA, P, T, M> {
        self.update(insertion, vec![])
    }

    fn delete<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, P, T>>(
        &mut self,
        deletion: impl IntoIterator<Item = Rule<P, A>>,
    ) -> InverseModel<OA, P, T, M> {
        self.update(vec![], deletion)
    }
}

/// A rule store and IM generator of a device. 
///
/// Generic parameters:
/// - `A`: [Action<Single>] type, which is used to represent the action of a FIB rule.
/// - `ME`: [MatchEncoder] type, which is used provide default "match any packet" predicate for
///   the default rule.
/// - `RS`: [RuleStore] type, which is used to store the rules.
pub struct FastRuleMonitor<'p, A, ME, RS>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
    RS: RuleStore<A, ME::P>,
{
    engine: &'p ME,
    i_rules: BinaryHeap<RcRule<ME::P, A>>,
    d_rules: BinaryHeap<RcRule<ME::P, A>>,
    default_rule: RcRule<ME::P, A>,
    local_ap: UnsafeCell<FxHashMap<A, Predicate<ME::P>>>,

    store: RS,
}

impl<'p, A, ME, RS> RuleMonitor<A, ME::P> for FastRuleMonitor<'p, A, ME, RS>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
    RS: RuleStore<A, ME::P>,
{
    fn clear(&mut self) {
        self.store.clear();
        self.i_rules.clear();
        self.d_rules.clear();
        self.i_rules.push(self.default_rule.clone());
    }

    fn update<OA, T, M>(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<ME::P, A>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T, M>
    where
        OA: Action<T, S = A>,
        T: Dimension,
        M: InverseModelMonoid<OA, ME::P, T>,
    {
        let firse_time = !self.i_rules.is_empty();
        insertion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.store.insert(r.clone());
            self.i_rules.push(r.clone());
        });
        deletion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.store.delete(&r);
            self.d_rules.push(r.clone());
        });
        let im = self.refresh();
        if firse_time {
            self.store.insert(self.default_rule.clone());
        }
        im
    }
}

impl<'p, A, ME, RS> FastRuleMonitor<'p, A, ME, RS>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
    RS: RuleStore<A, ME::P>,
{
    fn refresh<OA, T, M>(&mut self) -> InverseModel<OA, ME::P, T, M>
    where
        OA: Action<T, S = A>,
        T: Dimension,
        M: InverseModelMonoid<OA, ME::P, T>,
    {
        unsafe { (*self.local_ap.get()).clear() };
        let mut no_overwrite = self.engine.one();
        while let Some(r) = self.i_rules.pop() {
            let mut eff = r.predicate.clone();
            let related = self.store.search(&r);
            // effective predicate minus all higher priority predicates
            for y in related.clone().filter(|re| re.priority > r.priority) {
                eff -= &y.predicate;
                if eff.is_empty() {
                    break;
                }
            }
            // if eff is not empty, then the action is valid
            if !eff.is_empty() {
                unsafe { &mut *self.local_ap.get() }
                    .entry(r.action.clone())
                    .and_modify(|mut p| p |= &eff)
                    .or_insert(eff.clone());
                no_overwrite -= &eff;
            }
        }

        while let Some(r) = self.d_rules.pop() {
            let related = self.store.search(&r);
            let mut to_divide = r.predicate.clone();
            // to_divide minus all higher priority predicates
            for y in related.clone().filter(|re| re.priority > r.priority) {
                to_divide -= &y.predicate;
                if to_divide.is_empty() {
                    break;
                }
            }
            // if to_divide is still not empty, then it means if the rule is removed, the hiden
            // rules (variable y below) that are lower priority than it will be revealed
            while !to_divide.is_empty() {
                for y in related.clone().filter(|re| re.priority < r.priority).rev() {
                    let eff = &y.predicate & &to_divide;
                    if !eff.is_empty() {
                        unsafe { &mut *self.local_ap.get() }
                            .entry(y.action.clone())
                            .and_modify(|mut p| p |= &eff)
                            .or_insert(eff.clone());
                        no_overwrite -= &eff;
                        to_divide -= &eff;
                        if to_divide.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
        if !no_overwrite.is_empty() {
            unsafe { &mut *self.local_ap.get() }.insert(A::no_overwrite(), no_overwrite);
        }

        InverseModel::from(
            unsafe { &mut *self.local_ap.get() }
                .drain()
                .map(|(a, p)| (OA::from_single(a.clone()), p.clone())),
        )
    }

    pub fn new(engine: &'p ME) -> Self {
        // this is the default rule of every forwarding device
        let drop_rule = Rc::new(Rule {
            priority: -1,
            action: A::default_action(),
            predicate: engine.one(),
            origin: vec![MaskedValue::default()],
        });
        let local_ap = HashMap::with_hasher(FxBuildHasher::default());
        FastRuleMonitor {
            engine,
            i_rules: BinaryHeap::from([drop_rule.clone()]),
            d_rules: BinaryHeap::new(),
            default_rule: drop_rule,
            local_ap: UnsafeCell::new(local_ap),
            store: RS::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use fxhash::FxHashMap;
    use rapimt_core::prelude::RuddyPredicateEngine;
    use rapimt_io::prelude::{DefaultInstLoader, FibLoader, InstanceLoader, TypedAction};

    use super::*;

    #[test]
    fn test_default_fib_monitor() {
        let spec = r#"
        name dev0
        neighbor ge0 dev1
        neighbor ge1 dev2
        port gi0 ecmp ge0 ge1
        port gi1 flood ge0 ge1
        "#;
        let fib = r#"
        name dev0
        fw 0.0.0.0 1 1 ge0
        fw 192.168.1.0 24 24 gi0
        "#;
        // load port information
        let loader = DefaultInstLoader::default();
        let codex = InstanceLoader::load(&loader, spec).unwrap();

        // load fibs
        let engine = RuddyPredicateEngine::init(100, 100);

        // load fib rules and encode action to usize with codex
        let (_, fibs) = FibLoader::<usize>::load(&codex, &engine, fib).unwrap();

        // setup fib monitor
        let mut fib_monitor = FastRuleMonitor::<_, _, TPTRuleStore<_, _>>::new(&engine);

        // two rules as an incremental update
        // im should have three entries: one default "drop", one 0.0.0.0/1 and one "192.168.1.0/24"
        let im = fib_monitor.insert::<_, _, FxHashMap<usize, _>>(fibs.clone());
        assert_eq!(im.len(), 3);

        fib_monitor.clear();
        let im = fib_monitor.insert::<_, _, FxHashMap<usize, _>>(fibs);
        assert_eq!(im.len(), 3);

        let im = InverseModel::<_, _, _, FxHashMap<Vec<usize>, _>>::from(im);
        assert_eq!(im.len(), 3);

        // load fib rules and encode action to TypedAction with codex, run the same as above
        let (_, fibs) = FibLoader::<TypedAction>::load(&codex, &engine, fib).unwrap();
        let mut fib_monitor = FastRuleMonitor::<_, _, TPTRuleStore<_, _>>::new(&engine);
        let im = fib_monitor.insert::<_, _, FxHashMap<TypedAction, _>>(fibs);
        assert_eq!(im.len(), 3);
    }
}
