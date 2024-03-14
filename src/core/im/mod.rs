use crate::core::r#match::{MaskedValue, Predicate};
use crate::io::CodedAction;

pub struct Rule<P: Predicate, A: CodedAction = u32> {
  pub priority: u32,
  pub action: A,
  pub predicate: P,
  pub origin: Vec<MaskedValue>,
}
