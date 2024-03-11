use crate::core::action::Actions;

#[derive(Eq, PartialEq, Debug)]
struct SeqActions {
    n_dim: usize,
    actions: Vec<u64>,
}

impl Actions for SeqActions {
    type Impl = Vec<u64>;

    fn get_impl(&self) -> &Self::Impl {
        return &self.actions;
    }

    fn get(&self, idx: usize) -> u64 {
        return self.actions[idx];
    }

    fn resize(&self, to: usize, offset: usize) -> Self {
        assert!(to > offset);
        let mut new_actions: Vec<u64> = vec![0; to];
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

    fn update(mut self, pos: usize, value: u64) -> Self {
        assert!(pos < self.n_dim);
        self.actions[pos] = value;
        return self;
    }

    fn diff(&self, rhs: &Self) -> u64 {
        assert_eq!(self.n_dim, rhs.n_dim);
        let mut diff: u64 = 0;
        for i in 0..self.n_dim {
            if self.actions[i] != rhs.actions[i] {
                diff += 1;
            }
        }
        return diff;
    }

    fn overwrite(&self, rhs: &Self) -> Self {
        assert_eq!(self.n_dim, rhs.n_dim);
        let mut new_actions: Vec<u64> = vec![0; self.n_dim];
        for i in 0..self.n_dim {
            new_actions[i] = if rhs.actions[i] != 0 {
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

impl SeqActions {
    fn new(a: u64) -> Self {
        SeqActions {
            n_dim: 1,
            actions: vec![a; 1],
        }
    }

    fn new_with_dim(data: Vec<u64>) -> Self {
        SeqActions {
            n_dim: data.len(),
            actions: data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_actions_get() {
        let b = SeqActions::new_with_dim(vec![1, 2, 3]);
        assert_eq!(b.get(2), 3);
    }

    #[test]
    fn test_seq_actions_resize() {
        let a = SeqActions::new(1);
        let b = a.resize(3, 2);
        assert_eq!(b.get(1), 0);
        assert_eq!(b.get(2), 1);
        let c = SeqActions::new_with_dim(vec![1, 2, 3]);
        let d = c.resize(2, 0);
        assert_eq!(d.get(1), 2);
    }

    #[test]
    fn test_seq_actions_update() {
        let c = SeqActions::new_with_dim(vec![1, 2, 3]);
        let d = c.update(2, 4);
        assert_eq!(d.get(2), 4);
    }

    #[test]
    fn test_seq_actions_diff() {
        let a = SeqActions::new(1);
        let b = SeqActions::new(2);
        assert_eq!(a.diff(&b), 1);
        let c = SeqActions::new_with_dim(vec![1, 2, 3]);
        let d = SeqActions::new_with_dim(vec![1, 3, 4]);
        assert_eq!(c.diff(&d), 2);
    }

    #[test]
    fn test_seq_actions_overwrite() {
        let a = SeqActions::new(1);
        let b = SeqActions::new(2);
        let c = a.overwrite(&b);
        assert_eq!(c.get(0), 2);
        assert_eq!(a.get(0), 1);
        let d = SeqActions::new_with_dim(vec![1, 2, 3]);
        let e = SeqActions::new_with_dim(vec![1, 0, 4]);
        let f = d.overwrite(&e);
        assert_eq!(f.get_impl(), &[1, 2, 4]);
    }
}
