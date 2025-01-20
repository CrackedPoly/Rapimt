use crate::action::Actions;

use super::{Action, Multiple, Single};

impl<A: Action<Single>> Action<Multiple> for Vec<A> {
    type S = A;

    #[inline]
    fn default_action() -> Self {
        vec![A::default_action()]
    }

    #[inline]
    fn no_overwrite() -> Self {
        vec![A::no_overwrite()]
    }

    #[inline]
    fn overwrite(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.len(), rhs.len());
        let n_dim = self.len();
        let mut new_actions = Vec::with_capacity(self.capacity());
        for i in 0..n_dim {
            if rhs[i] != A::no_overwrite() {
                new_actions.push(rhs[i].clone());
            } else {
                new_actions.push(self[i].clone());
            }
        }
        new_actions
    }

    #[inline]
    fn overwrite_(&mut self, rhs: &Self) {
        debug_assert_eq!(self.len(), rhs.len());
        let n_dim = self.len();
        for i in 0..n_dim {
            if rhs[i] != A::no_overwrite() {
                self[i] = rhs[i].clone();
            }
        }
    }

    #[inline]
    fn from_single(single: Self::S) -> Self {
        vec![single]
    }
}

impl<A: Action<Single> + Copy> Actions for Vec<A> {
    fn len(&self) -> usize {
        self.len()
    }

    fn resize_(&mut self, to: usize, offset: usize) {
        let n_dim = self.len();
        if to > self.capacity() {
            self.reserve(to - n_dim);
        }
        if to > n_dim {
            self.resize(to, A::no_overwrite());
        }
        if offset > 0 {
            self.copy_within(0..n_dim, offset);
            self[..offset].fill(A::no_overwrite());
        }
    }

    fn diff(&self, rhs: &Self) -> usize {
        debug_assert_eq!(self.len(), rhs.len());
        let n_dim = self.len();
        let mut diff: usize = 0;
        for i in 0..n_dim {
            if self[i] != rhs[i] {
                diff += 1;
            }
        }
        diff
    }

    fn index(&self, index: usize) -> &Self::S {
        &self[index]
    }

    fn index_mut(&mut self, index: usize) -> &mut Self::S {
        &mut self[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_actions_get() {
        let b = Vec::from(&[1, 2, 3]);
        assert_eq!(b[2], 3);
    }

    #[test]
    fn test_seq_actions_resize() {
        let mut a = Vec::from(&[1]);
        a.resize_(3, 2);
        assert_eq!(a[1], 0);
        assert_eq!(a[2], 1);
        let mut b = Vec::from(&[1, 2, 3]);
        b.resize_(2, 0);
        assert_eq!(b[1], 2);
    }

    #[test]
    fn test_seq_actions_update() {
        let mut c = Vec::from(&[1, 2, 3]);
        c[2] = 4;
        assert_eq!(c[2], 4);
    }

    #[test]
    fn test_seq_actions_diff() {
        let a = Vec::from(&[1]);
        let b = Vec::from(&[2]);
        assert_eq!(a.diff(&b), 1);
        let c = Vec::from(&[1, 2, 3]);
        let d = Vec::from(&[1, 3, 4]);
        assert_eq!(c.diff(&d), 2);
    }

    #[test]
    fn test_seq_actions_overwrite() {
        let a = Vec::from(&[1]);
        let b = Vec::from(&[2]);
        let a = a.overwrite(&b);
        assert_eq!(a[0], 2);
        let c = Vec::from(&[1, 2, 3]);
        let d = Vec::from(&[1, 0, 4]);
        let c = c.overwrite(&d);
        assert_eq!(c[0], 1);
        assert_eq!(c[1], 2);
        assert_eq!(c[2], 4);
    }
}
