use std::hash::Hash;
use std::ops::{Index, IndexMut};

use crate::io::CodedAction;

pub mod seq_action;

pub trait Actions<A: CodedAction>:
  From<Vec<A>> + Index<usize, Output = A> + IndexMut<usize, Output = A> + Hash + Eq
{
  fn len(&self) -> usize;
  fn resize(&mut self, to: usize, offset: usize);
  fn overwritten(&self, rhs: &Self) -> Self;
  fn diff(&self, rhs: &Self) -> usize;
}
