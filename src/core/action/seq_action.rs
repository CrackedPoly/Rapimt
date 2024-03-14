use crate::core::action::Actions;
use crate::io::CodedAction;

#[derive(Eq, PartialEq, Debug)]
pub struct SeqActions<A> {
  n_dim: usize,
  actions: Vec<A>,
}

impl<A: CodedAction> Actions<A> for SeqActions<A> {
  fn from(a: A) -> Self {
    SeqActions {
      n_dim: 1,
      actions: vec![a; 1],
    }
  }

  fn from_all(data: Vec<A>) -> Self {
    SeqActions {
      n_dim: data.len(),
      actions: data,
    }
  }

  fn get(&self, idx: usize) -> A {
    return self.actions[idx];
  }

  fn get_all(&self) -> &[A] {
    return &self.actions;
  }

  fn resize(&self, to: usize, offset: usize) -> Self {
    assert!(to > offset);
    let mut new_actions: Vec<A> = vec![A::default(); to];
    let n = to - offset;
    if n >= self.n_dim {
      new_actions[offset..offset + self.n_dim].clone_from_slice(&self.actions);
    } else {
      // n < self.n_dim
      new_actions[offset..to].clone_from_slice(&self.actions[0..n]);
    }
    SeqActions {
      n_dim: to,
      actions: new_actions,
    }
  }

  fn update(&mut self, idx: usize, value: A) {
    assert!(idx < self.n_dim);
    self.actions[idx] = value;
  }

  fn diff(&self, rhs: &Self) -> usize {
    assert_eq!(self.n_dim, rhs.n_dim);
    let mut diff: usize = 0;
    for i in 0..self.n_dim {
      if self.actions[i].into() != rhs.actions[i].into() {
        diff += 1;
      }
    }
    return diff;
  }

  fn overwrite(&self, rhs: &Self) -> Self {
    assert_eq!(self.n_dim, rhs.n_dim);
    let mut new_actions: Vec<A> = vec![A::default(); self.n_dim];
    for i in 0..self.n_dim {
      new_actions[i] = if rhs.actions[i].into() != 0 {
        rhs.actions[i]
      } else {
        self.actions[i]
      }
    }
    SeqActions {
      n_dim: self.n_dim,
      actions: new_actions,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_seq_actions_get() {
    let b = SeqActions::from_all(vec![1u32, 2, 3]);
    assert_eq!(b.get(2), 3);
  }

  #[test]
  fn test_seq_actions_resize() {
    let a = <SeqActions<_> as Actions<_>>::from(1u32);
    let b = a.resize(3, 2);
    assert_eq!(b.get(1), 0);
    assert_eq!(b.get(2), 1);
    let c = SeqActions::from_all(vec![1u32, 2, 3]);
    let d = c.resize(2, 0);
    assert_eq!(d.get(1), 2);
  }

  #[test]
  fn test_seq_actions_update() {
    let mut c = SeqActions::from_all(vec![1u32, 2, 3]);
    c.update(2, 4);
    assert_eq!(c.get(2), 4);
  }

  #[test]
  fn test_seq_actions_diff() {
    let a = <SeqActions<_> as Actions<_>>::from(1u32);
    let b = <SeqActions<_> as Actions<_>>::from(2u32);
    assert_eq!(a.diff(&b), 1);
    let c = SeqActions::from_all(vec![1, 2, 3]);
    let d = SeqActions::from_all(vec![1, 3, 4]);
    assert_eq!(c.diff(&d), 2);
  }

  #[test]
  fn test_seq_actions_overwrite() {
    let a = <SeqActions<_> as Actions<_>>::from(1u32);
    let b = <SeqActions<_> as Actions<_>>::from(2u32);
    let c = a.overwrite(&b);
    assert_eq!(c.get(0), 2);
    assert_eq!(a.get(0), 1);
    let d = SeqActions::from_all(vec![1, 2, 3]);
    let e = SeqActions::from_all(vec![1, 0, 4]);
    let f = d.overwrite(&e);
    assert_eq!(f.get_all(), &[1, 2, 4]);
  }
}
