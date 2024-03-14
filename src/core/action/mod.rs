use crate::io::CodedAction;

mod seq_action;

pub trait Actions<A: CodedAction> {
  fn from(a: A) -> Self;
  fn from_all(data: Vec<A>) -> Self;
  fn get(&self, idx: usize) -> A;
  fn get_all(&self) -> &[A];
  fn resize(&self, to: usize, offset: usize) -> Self;
  fn update(&mut self, idx: usize, value: A);
  fn diff(&self, rhs: &Self) -> usize;
  fn overwrite(&self, rhs: &Self) -> Self;
}
