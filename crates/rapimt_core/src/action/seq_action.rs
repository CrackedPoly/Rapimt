use std::{
    hash::Hash,
    ops::{Index, IndexMut},
};

use crate::action::{CodedAction, CodedActions};

use super::{Action, Multiple};

/// A sequence of actions stored in Vec. Generics `N` is the hint capacity of the Vec, which is
/// usually the network size.
#[derive(Eq, PartialEq, Hash, Debug)]
pub struct SeqActions<A: CodedAction, const N: usize>(Vec<A>);

impl<A: CodedAction, const N: usize> Action<Multiple> for SeqActions<A, N> {
    type S = A;
}

impl<A: CodedAction, const N: usize> From<A> for SeqActions<A, N> {
    #[inline]
    fn from(value: A) -> Self {
        let mut v = Vec::with_capacity(N);
        v.push(value);
        SeqActions(v)
    }
}

impl<A: CodedAction, const N: usize> Index<usize> for SeqActions<A, N> {
    type Output = A;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<A: CodedAction, const N: usize> IndexMut<usize> for SeqActions<A, N> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<A: CodedAction, const N: usize> CodedActions for SeqActions<A, N> {
    type A = A;
    const N: usize = N;

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    fn resize(&mut self, to: usize, offset: usize) {
        let n_dim = self.0.len();
        if to > self.0.capacity() {
            self.0.reserve(to - n_dim);
        }
        if to > n_dim {
            self.0.resize(to, A::default());
        }
        if offset > 0 {
            self.0.copy_within(0..n_dim, offset);
            self.0[..offset].fill(A::default());
        }
    }

    fn overwritten(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.0.len(), rhs.0.len());
        let n_dim = self.0.len();
        let mut new_actions = Vec::with_capacity(self.0.capacity());
        for i in 0..n_dim {
            if rhs[i] != A::default() {
                new_actions.push(rhs[i]);
            } else {
                new_actions.push(self[i]);
            }
        }
        SeqActions(new_actions)
    }

    fn diff(&self, rhs: &Self) -> usize {
        debug_assert_eq!(self.0.len(), rhs.0.len());
        let n_dim = self.0.len();
        let mut diff: usize = 0;
        for i in 0..n_dim {
            if self[i] != rhs[i] {
                diff += 1;
            }
        }
        diff
    }
}

impl<A: CodedAction, const N: usize> From<&[A; N]> for SeqActions<A, N> {
    fn from(value: &[A; N]) -> Self {
        let mut v = Vec::with_capacity(N);
        v.extend_from_slice(value);
        SeqActions(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_actions_get() {
        let b = SeqActions::from(&[1, 2, 3]);
        assert_eq!(b[2], 3);
    }

    #[test]
    fn test_seq_actions_resize() {
        let mut a = SeqActions::from(&[1]);
        a.resize(3, 2);
        assert_eq!(a[1], 0);
        assert_eq!(a[2], 1);
        let mut b = SeqActions::from(&[1, 2, 3]);
        b.resize(2, 0);
        assert_eq!(b[1], 2);
    }

    #[test]
    fn test_seq_actions_update() {
        let mut c = SeqActions::from(&[1, 2, 3]);
        c[2] = 4;
        assert_eq!(c[2], 4);
    }

    #[test]
    fn test_seq_actions_diff() {
        let a = SeqActions::from(&[1]);
        let b = SeqActions::from(&[2]);
        assert_eq!(a.diff(&b), 1);
        let c = SeqActions::from(&[1, 2, 3]);
        let d = SeqActions::from(&[1, 3, 4]);
        assert_eq!(c.diff(&d), 2);
    }

    #[test]
    fn test_seq_actions_overwrite() {
        let a = SeqActions::from(&[1]);
        let b = SeqActions::from(&[2]);
        let a = a.overwritten(&b);
        assert_eq!(a[0], 2);
        let c = SeqActions::from(&[1, 2, 3]);
        let d = SeqActions::from(&[1, 0, 4]);
        let c = c.overwritten(&d);
        assert_eq!(c[0], 1);
        assert_eq!(c[1], 2);
        assert_eq!(c[2], 4);
    }
}
