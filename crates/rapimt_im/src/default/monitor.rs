use std::{
    cell::UnsafeCell,
    collections::{BTreeSet, BinaryHeap, HashMap},
    rc::Rc,
};

use fxhash::{FxBuildHasher, FxHashMap};
use rapimt_core::prelude::{
    constant, Action, Dimension, MaskedValue, MatchEncoder, Predicate, PredicateInner, Single,
};
use rapimt_tpt::prelude::{Segmentizer, TernaryPatriciaTree};

use crate::im::{InverseModel, InverseModelMonoid, MapMonoid};
use crate::{default::rule::Rule, RuleMonitorLike};

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

/// A rule store and IM generator of a device.
///
/// Generic parameters:
/// - `A`: [`Action<Single>`] type, which is used to represent the action of a FIB rule.
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
    store: RS,

    i_rules: BinaryHeap<RcRule<ME::P, A>>,
    d_rules: BinaryHeap<RcRule<ME::P, A>>,
    default_rule: RcRule<ME::P, A>,

    tmp_ow: UnsafeCell<FxHashMap<A, Predicate<ME::P>>>,
}

impl<'p, A, OA, T, ME, RS, S>
    RuleMonitorLike<A, OA, T, MapMonoid<OA, Predicate<ME::P>, S>, ME::P, Rule<ME::P, A>>
    for FastRuleMonitor<'p, A, ME, RS>
where
    A: Action<Single>,
    OA: Action<T, S = A>,
    T: Dimension,
    ME: MatchEncoder<'p>,
    RS: RuleStore<A, ME::P>,
    S: std::hash::BuildHasher + std::clone::Clone + std::default::Default,
{
    /// Clears all rules and resets the monitor to its default state.
    ///
    /// Removes all inserted and deleted rules from the monitor, clears the underlying rule store,
    /// and re-inserts the default rule as the only active rule.
    ///
    /// # Examples
    ///
    /// ```
    /// monitor.clear();
    /// // Only the default rule remains active after clearing.
    /// ```
    fn clear(&mut self) {
        self.store.clear();
        self.i_rules.clear();
        self.d_rules.clear();
        self.i_rules.push(self.default_rule.clone());
    }

    /// Updates the rule monitor by applying rule insertions and deletions, then recomputes and returns the inverse model.
    ///
    /// This method inserts new rules and deletes specified rules from the internal store, updates the corresponding heaps,
    /// and refreshes the inverse model to reflect the current rule set. If this is the first update, the default rule is also inserted.
    ///
    /// # Parameters
    /// - `insertion`: An iterable collection of rules to be inserted.
    /// - `deletion`: An iterable collection of rules to be deleted.
    ///
    /// # Returns
    /// An `InverseModel` mapping output actions to predicates, representing the current state of the rule set.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut monitor = FastRuleMonitor::new(engine, store);
    /// let rules_to_add = vec![rule1, rule2];
    /// let rules_to_remove = vec![rule3];
    /// let inverse_model = monitor.update(rules_to_add, rules_to_remove);
    /// // `inverse_model` now reflects the updated rule set.
    /// ```
    fn update(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<ME::P, A>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T, MapMonoid<OA, Predicate<ME::P>, S>> {
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
        unsafe { (*self.tmp_ow.get()).clear() };
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
                unsafe { &mut *self.tmp_ow.get() }
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
                        unsafe { &mut *self.tmp_ow.get() }
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
            unsafe { &mut *self.tmp_ow.get() }.insert(A::no_overwrite(), no_overwrite);
        }

        InverseModel::from(
            unsafe { &mut *self.tmp_ow.get() }
                .drain()
                .map(|(a, p)| (OA::from_single(a), p)),
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
            tmp_ow: UnsafeCell::new(local_ap),
            store: RS::default(),
        }
    }
}
