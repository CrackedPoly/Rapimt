use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::marker::PhantomData;
use std::rc::Rc;

use crate::core::action::CodedActions;
use crate::core::im::{FibMonitor, InverseModel, ModelEntry};
use crate::core::r#match::Rule;
use crate::core::r#match::{MaskedValue, MatchEncoder, Predicate, PredicateInner};
use crate::io::{ActionEncoder, CodedAction, UncodedAction};

#[allow(dead_code)]
#[derive(Debug)]
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
  rules: BTreeSet<Rc<Rule<P, A>>>,
  i_rules: Vec<Rc<Rule<P, A>>>,
  d_rules: Vec<Rule<P, A>>,
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
    self.rules.clear();
    self.i_rules.clear();
    self.d_rules.clear();
  }

  fn update<As: CodedActions<A>>(
    &mut self,
    insertion: Vec<Rule<P, A>>,
    deletion: Vec<Rule<P, A>>,
  ) -> InverseModel<P, A, As> {
    self.i_rules.iter().for_each(|r| {
      self.rules.insert(r.clone());
    });
    insertion.into_iter().for_each(|r| {
      let r = Rc::new(r);
      if self.rules.insert(r.clone()) {
        self.i_rules.push(r.clone());
      } else {
        dbg!(&r);
        dbg!(&self.rules);
      }
    });
    deletion.into_iter().for_each(|r| {
      if self.rules.remove(&r) {
        self.d_rules.push(r);
      }
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
  pub fn new(engine: &'p ME, codex: &'a AE, dim_hint: usize) -> Self {
    let drop_rule = Rule {
      priority: -1,
      action: codex.encode(codex.lookup("self")),
      predicate: engine.one(),
      origin: vec![MaskedValue::from((0u32, 0u32))],
    };
    let mut rules = BTreeSet::new();
    rules.insert(Rc::new(drop_rule));
    let i_rules = Vec::new();
    let d_rules = Vec::new();
    let local_ap = HashMap::new();
    DefaultFibMonitor {
      engine,
      codex,
      local_ap,
      rules,
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
    self.i_rules.iter().for_each(|r| {
      let higher = self.rules.iter().filter(|y| y.priority > r.priority);
      let mut eff = r.predicate.clone();
      for y in higher {
        eff -= &y.predicate;
        if eff.is_empty() {
          break;
        }
      }
      if !eff.is_empty() {
        self
          .local_ap
          .entry(r.action)
          .and_modify(|p| *p |= &eff)
          .or_insert(eff.clone());
        no_overwrite -= &eff;
      }
    });
    self.d_rules.iter().for_each(|r| {
      let (higher, lower_eq): (Vec<_>, Vec<_>) = self.rules.iter().partition(|y| y.priority > r.priority);
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
            self
              .local_ap
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
    self
      .local_ap
      .iter()
      .map(|(a, p)| {
        let actions = if self.dim_hint > 0 {
          let mut vec = Vec::with_capacity(self.dim_hint);
          vec.push(*a);
          As::from(vec)
        } else {
          As::from(vec![*a])
        };
        ModelEntry {
          actions,
          predicate: p.clone(),
          _phantom: PhantomData,
        }
      })
      .collect::<Vec<_>>()
      .into()
  }
}

#[cfg(test)]
mod test {
  use crate::core::action::seq_action::SeqActions;
  use crate::core::im::monitor::DefaultFibMonitor;
  use crate::core::im::FibMonitor;
  use crate::core::r#match::family::MatchFamily;
  use crate::core::r#match::RuddyPredicateEngine;
  use crate::io::default::DefaultInstLoader;
  use crate::io::{FibLoader, InstanceLoader};

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
        fw 0.0.0.0 0 0 ge0
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

    // default "drop" ("self") rule as incremental update
    let im = fib_monitor.update::<SeqActions<u32>>(vec![], vec![]);
    assert_eq!(im.size, 1);
    // two rules as an incremental update, one is no overwrite, another is overwriting 192.168.1.0/24
    let im = fib_monitor.insert::<SeqActions<u32>>(fibs);
    assert_eq!(im.size, 2);
    assert_eq!(fib_monitor.rules.len(), 3);
  }
}
