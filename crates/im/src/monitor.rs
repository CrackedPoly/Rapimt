use std::{cmp::Reverse, collections::HashMap, collections::HashSet, rc::Rc};

use rapimt_core::{
    action::{ActionEncoder, CodedAction, CodedActions, UncodedAction},
    r#match::{MaskedValue, MatchEncoder, Predicate, PredicateInner, Rule},
    MAX_POS,
};
use rapimt_tpt::{Segmentizer, TernaryPatriciaTree};

use crate::{
    im::{InverseModel, ModelEntry},
    FibMonitor,
};

#[allow(dead_code)]
pub struct DefaultFibMonitor<'a, 'p, P, ME, A, AE>
where
    P: PredicateInner,
    ME: MatchEncoder<'p>,
    A: CodedAction,
    AE: ActionEncoder<'a, A>,
{
    engine: &'p ME,
    codex: &'a AE,
    local_ap: HashMap<A, Predicate<P>>,
    tpt: TernaryPatriciaTree<Rc<Rule<P, A>>>,
    i_rules: Vec<Rc<Rule<P, A>>>,
    d_rules: Vec<Rc<Rule<P, A>>>,
    dim_hint: usize,
}

impl<'a, 'p, P, ME, A, AE> FibMonitor<P, A> for DefaultFibMonitor<'a, 'p, P, ME, A, AE>
where
    P: PredicateInner,
    ME: MatchEncoder<'p, P = P>,
    A: CodedAction,
    AE: ActionEncoder<'a, A>,
{
    fn clear(&mut self) {
        self.tpt.clear();
        self.i_rules.clear();
        self.d_rules.clear();
    }

    fn update<As: CodedActions<A>>(
        &mut self,
        insertion: Vec<Rule<P, A>>,
        deletion: Vec<Rule<P, A>>,
    ) -> InverseModel<P, A, As> {
        insertion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.insert_tpt(r.clone());
            self.i_rules.push(r.clone());
        });
        deletion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.delete_tpt(r.clone());
            self.d_rules.push(r.clone());
        });
        self.refresh();
        self.current()
    }
}

impl<'a, 'p, P, ME, UA, A, AE> DefaultFibMonitor<'a, 'p, P, ME, A, AE>
where
    P: PredicateInner,
    ME: MatchEncoder<'p, P = P>,
    UA: UncodedAction,
    A: CodedAction,
    AE: ActionEncoder<'a, A, UA = UA>,
{
    fn insert_tpt(&mut self, rule: Rc<Rule<P, A>>) {
        rule.as_ref().origin.iter().for_each(|mv| {
            self.tpt
                .insert(rule.clone(), Segmentizer::from(*mv));
        });
    }

    fn delete_tpt(&mut self, rule: Rc<Rule<P, A>>) {
        rule.as_ref().origin.iter().for_each(|mv| {
            self.tpt
                .delete(rule.clone(), Segmentizer::from(*mv));
        });
    }

    fn search_tpt(&self, rule: Rc<Rule<P, A>>) -> HashSet<Rc<Rule<P, A>>> {
        rule.as_ref()
            .origin
            .iter()
            .fold(HashSet::new(), |mut set, mv| {
                set.extend(
                    self.tpt
                        .search(rule.clone(), Segmentizer::from(*mv)),
                );
                set
            })
    }

    pub fn new(engine: &'p ME, codex: &'a AE, dim_hint: usize) -> Self {
        // this is the default rule of every forwarding device
        let drop_rule = Rc::new(Rule {
            priority: -1,
            action: codex.encode(codex.lookup("self")),
            predicate: engine.one(),
            origin: vec![MaskedValue::from((0u128, 0u128))],
        });
        let mut tpt = TernaryPatriciaTree::new(MAX_POS);
        drop_rule.as_ref().origin.iter().for_each(|mv| {
            tpt.insert(drop_rule.clone(), Segmentizer::from(*mv));
        });
        let i_rules = Vec::new();
        let d_rules = Vec::new();
        let local_ap = HashMap::new();
        DefaultFibMonitor {
            engine,
            codex,
            local_ap,
            tpt,
            i_rules,
            d_rules,
            dim_hint,
        }
    }

    fn refresh(&mut self) {
        self.i_rules.sort_by_key(|r| Reverse(r.priority));
        self.d_rules.sort_by_key(|r| Reverse(r.priority));
        self.local_ap.clear();
        let mut no_overwrite = self.engine.one();
        self.i_rules.clone().iter().for_each(|r| {
            let higher = self
                .search_tpt(r.clone())
                .into_iter()
                .filter(|y| y.priority > r.priority);
            let mut eff = r.predicate.clone();
            for y in higher {
                eff -= &y.predicate;
                if eff.is_empty() {
                    break;
                }
            }
            if !eff.is_empty() {
                self.local_ap
                    .entry(r.action)
                    .and_modify(|p| *p |= &eff)
                    .or_insert(eff.clone());
                no_overwrite -= &eff;
            }
        });
        self.d_rules.clone().iter().for_each(|r| {
            let (higher, lower_eq): (Vec<_>, Vec<_>) = self
                .search_tpt(r.clone())
                .into_iter()
                .partition(|y| y.priority > r.priority);
            let mut to_divide = r.predicate.clone();
            for y in &higher {
                to_divide -= &y.predicate;
                if to_divide.is_empty() {
                    break;
                }
            }
            while !to_divide.is_empty() {
                for y in &lower_eq {
                    let eff = &y.predicate & &to_divide;
                    if !eff.is_empty() {
                        self.local_ap
                            .entry(y.action)
                            .and_modify(|p| *p |= &eff)
                            .or_insert(eff.clone());
                        no_overwrite -= &eff;
                        to_divide -= &eff;
                        if to_divide.is_empty() {
                            break;
                        }
                    }
                }
            }
        });
        if !no_overwrite.is_empty() {
            self.local_ap.insert(A::default(), no_overwrite);
        }
        self.i_rules.clear();
        self.d_rules.clear();
    }

    fn current<As: CodedActions<A>>(&self) -> InverseModel<P, A, As> {
        self.local_ap
            .iter()
            .map(|(a, p)| {
                let actions = if self.dim_hint > 0 {
                    let mut vec = Vec::with_capacity(self.dim_hint);
                    vec.push(*a);
                    As::from(vec)
                } else {
                    As::from(vec![*a])
                };
                ModelEntry::from((actions, p.clone()))
            })
            .collect::<Vec<_>>()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use rapimt_core::{
        action::seq_action::SeqActions,
        r#match::{engine::RuddyPredicateEngine, family::MatchFamily},
    };
    use rapimt_io::{DefaultInstLoader, FibLoader, InstanceLoader};

    use crate::monitor::DefaultFibMonitor;
    use crate::FibMonitor;

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
        fw 192.168.1.0 24 24 gi0
        fw 0.0.0.0 1 1 ge0
        "#;
        // load port information
        let parser = DefaultInstLoader::default();
        let codex = InstanceLoader::load(&parser, spec).unwrap();

        // load fibs
        let family = MatchFamily::Inet4Family;
        let mut engine = RuddyPredicateEngine::default();
        engine.init(1000, 100, family);
        let (_, fibs) = FibLoader::load(&codex, &engine, fib).unwrap();

        // setup fib monitor
        let mut fib_monitor = DefaultFibMonitor::new(&engine, &codex, 0);

        // two rules as an incremental update
        // im should have three entries: one default "drop", one 0.0.0.0/1 and one "192.168.1.0/24"
        let im = fib_monitor.insert::<SeqActions<u32>>(fibs);
        assert_eq!(im.size, 3);
    }
}
