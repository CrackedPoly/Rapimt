use crate::action::Actions;

use super::{Action, Multiple, Single};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum Kind {
    One,
    Many,
}

/// A sequence of actions. Optimize memory footprint when the action is valid in one dimension.
///
/// When kind is `One`, the action is a single action and `len` is the index of the action. When
/// kind is `Many`, the action is a sequence of actions which is identical to a vec.
#[derive(Eq)]
pub struct SeqAction<A: Action<Single> + Copy> {
    kind: Kind,
    ptr: *mut A,
    len: usize,
    ndim: usize,
    _noov: A,
}

impl<A: Action<Single> + Copy> SeqAction<A> {
    fn new_one(action: A) -> *mut A {
        Box::into_raw(Box::new(action))
    }

    fn new_many(ndim: usize) -> *mut A {
        let mut vec = Vec::with_capacity(ndim);
        for _ in 0..ndim {
            vec.push(A::no_overwrite());
        }
        let (ptr, _, _) = vec.into_raw_parts();
        ptr
    }

    fn drop_inner(&mut self) {
        match self.kind {
            Kind::One => unsafe {
                drop(Box::from_raw(self.ptr));
            },
            Kind::Many => {
                unsafe { drop(std::vec::Vec::from_raw_parts(self.ptr, self.len, self.ndim)) };
            }
        }
    }
}

impl<A: Action<Single> + Copy> std::fmt::Debug for SeqAction<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            Kind::One => {
                let ptr = Self::new_many(self.ndim);
                let vec = unsafe {
                    *ptr.add(self.len) = *self.ptr;
                    Vec::from_raw_parts(ptr, self.ndim, self.ndim)
                };
                write!(f, "SeqAction({:?})", vec)?;
                std::mem::forget(vec);
                Ok(())
            }
            Kind::Many => {
                let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.ndim) };
                write!(f, "SeqAction({:?})", slice)
            }
        }
    }
}

impl<A: Action<Single> + Copy> std::hash::Hash for SeqAction<A> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self.kind {
            Kind::One => {
                state.write_length_prefix(self.ndim);
                for i in 0..self.ndim {
                    self.index(i).hash(state);
                }
            }
            Kind::Many => {
                let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.ndim) };
                slice.hash(state);
            }
        }
    }
}

impl<A: Action<Single> + Copy> std::cmp::PartialEq for SeqAction<A> {
    fn eq(&self, other: &Self) -> bool {
        if self.ndim != other.ndim {
            return false;
        }
        match (self.kind, other.kind) {
            (Kind::Many, Kind::Many) => {
                let slice1 = unsafe { std::slice::from_raw_parts(self.ptr, self.ndim) };
                let slice2 = unsafe { std::slice::from_raw_parts(other.ptr, other.ndim) };
                return slice1 == slice2;
            }
            _ => {
                for i in 0..self.ndim {
                    if self.index(i) != other.index(i) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl<A: Action<Single> + Copy> Clone for SeqAction<A> {
    fn clone(&self) -> Self {
        match self.kind {
            Kind::One => SeqAction {
                kind: Kind::One,
                ptr: unsafe { Box::into_raw(Box::new(*self.ptr)) },
                len: self.len,
                ndim: self.ndim,
                _noov: A::no_overwrite(),
            },
            Kind::Many => {
                let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.ndim) };
                let new_vec = Vec::from(slice);
                let (new_ptr, new_len, new_ndim) = new_vec.into_raw_parts();
                Self {
                    kind: Kind::Many,
                    ptr: new_ptr,
                    len: new_len,
                    ndim: new_ndim,
                    _noov: A::no_overwrite(),
                }
            }
        }
    }
}

unsafe impl<A: Action<Single> + Copy + Send> Send for SeqAction<A> {}
unsafe impl<A: Action<Single> + Copy + Sync> Sync for SeqAction<A> {}

impl<A: Action<Single> + Copy> Action<Multiple> for SeqAction<A> {
    type S = A;

    fn default_action() -> Self {
        SeqAction {
            kind: Kind::One,
            ptr: Box::into_raw(Box::new(A::default_action())),
            len: 0,
            ndim: 1,
            _noov: A::no_overwrite(),
        }
    }

    fn no_overwrite() -> Self {
        SeqAction {
            kind: Kind::One,
            ptr: Box::into_raw(Box::new(A::no_overwrite())),
            len: 0,
            ndim: 1,
            _noov: A::no_overwrite(),
        }
    }

    fn overwritten(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.ndim, rhs.ndim);
        match (self.kind, rhs.kind) {
            (Kind::One, Kind::One) => {
                if self.len == rhs.len {
                    if unsafe { *rhs.ptr } == A::no_overwrite() {
                        self.clone()
                    } else {
                        rhs.clone()
                    }
                } else {
                    let new_ptr = Self::new_many(self.ndim);
                    unsafe {
                        std::ptr::write(new_ptr.add(self.len), *self.ptr);
                        std::ptr::write(new_ptr.add(rhs.len), *rhs.ptr);
                    }
                    SeqAction {
                        kind: Kind::Many,
                        ptr: new_ptr,
                        len: self.ndim,
                        ndim: self.ndim,
                        _noov: A::no_overwrite(),
                    }
                }
            }
            (Kind::One, Kind::Many) => {
                let new_ptr = Self::new_many(rhs.ndim);
                unsafe {
                    std::ptr::copy_nonoverlapping(rhs.ptr, new_ptr, rhs.ndim);
                    if *rhs.ptr.add(self.len) == A::no_overwrite() {
                        std::ptr::write(new_ptr.add(self.len), *self.ptr);
                    }
                }
                SeqAction {
                    kind: Kind::Many,
                    ptr: new_ptr,
                    len: rhs.len,
                    ndim: rhs.ndim,
                    _noov: A::no_overwrite(),
                }
            }
            (Kind::Many, Kind::One) => {
                let new_ptr = Self::new_many(self.ndim);
                unsafe {
                    std::ptr::copy_nonoverlapping(self.ptr, new_ptr, self.ndim);
                    if *rhs.ptr != A::no_overwrite() {
                        std::ptr::write(new_ptr.add(rhs.len), *rhs.ptr);
                    }
                }
                SeqAction {
                    kind: Kind::Many,
                    ptr: new_ptr,
                    len: self.len,
                    ndim: self.ndim,
                    _noov: A::no_overwrite(),
                }
            }
            (Kind::Many, Kind::Many) => {
                let new_ptr = Self::new_many(self.ndim);
                unsafe {
                    std::ptr::copy_nonoverlapping(self.ptr, new_ptr, self.ndim);
                }
                for i in 0..rhs.len {
                    unsafe {
                        if *rhs.ptr.add(i) != A::no_overwrite() {
                            std::ptr::write(new_ptr.add(i), *rhs.ptr.add(i));
                        }
                    }
                }
                SeqAction {
                    kind: Kind::Many,
                    ptr: new_ptr,
                    len: self.len.max(rhs.len),
                    ndim: self.ndim.max(rhs.ndim),
                    _noov: A::no_overwrite(),
                }
            }
        }
    }

    fn overwritten_(&mut self, rhs: &Self) {
        debug_assert_eq!(self.ndim, rhs.ndim);
        match (self.kind, rhs.kind) {
            (Kind::One, Kind::One) => {
                if self.len == rhs.len {
                    if unsafe { *rhs.ptr } != A::no_overwrite() {
                        unsafe {
                            std::ptr::write(self.ptr, *rhs.ptr);
                        }
                    }
                } else {
                    let new_ptr = Self::new_many(self.ndim);
                    unsafe {
                        std::ptr::write(new_ptr.add(self.len), *self.ptr);
                        std::ptr::write(new_ptr.add(rhs.len), *rhs.ptr);
                    }
                    self.drop_inner();
                    self.kind = Kind::Many;
                    self.ptr = new_ptr;
                    self.len = self.ndim;
                }
            }
            (Kind::One, Kind::Many) => {
                let new_ptr = Self::new_many(rhs.ndim);
                unsafe {
                    std::ptr::copy_nonoverlapping(rhs.ptr, new_ptr, rhs.ndim);
                    if *rhs.ptr.add(self.len) != A::no_overwrite() {
                        std::ptr::write(new_ptr.add(self.len), *self.ptr);
                    }
                }
                self.drop_inner();
                self.kind = Kind::Many;
                self.ptr = new_ptr;
                self.len = rhs.len;
                self.ndim = rhs.ndim;
            }
            (Kind::Many, Kind::One) => unsafe {
                if *rhs.ptr != A::no_overwrite() {
                    std::ptr::write(self.ptr.add(rhs.len), *rhs.ptr);
                }
            },
            (Kind::Many, Kind::Many) => {
                for i in 0..rhs.len {
                    unsafe {
                        if *rhs.ptr.add(i) != A::no_overwrite() {
                            std::ptr::write(self.ptr.add(i), *rhs.ptr.add(i));
                        }
                    }
                }
            }
        }
    }

    fn from_single(single: Self::S) -> Self {
        let ptr = Self::new_one(single);
        Self {
            kind: Kind::One,
            ptr,
            len: 0,
            ndim: 1,
            _noov: A::no_overwrite(),
        }
    }
}

impl<A: Action<Single> + Copy> Actions for SeqAction<A> {
    fn ndim(&self) -> usize {
        self.ndim
    }

    fn diff(&self, rhs: &Self) -> usize {
        debug_assert_eq!(self.ndim, rhs.ndim);
        let mut diff = 0;
        for i in 0..self.ndim {
            if self.index(i) != rhs.index(i) {
                diff += 1;
            }
        }
        diff
    }

    fn resize_(&mut self, to: usize, offset: usize) {
        match self.kind {
            Kind::One => {
                self.ndim = to;
                self.len += offset;
            }
            Kind::Many => {
                let new_ptr = Self::new_many(to);
                for i in 0..self.len {
                    if i + offset >= to {
                        break;
                    }
                    unsafe {
                        std::ptr::write(new_ptr.add(i + offset), *self.ptr.add(i));
                    }
                }
                self.drop_inner();
                self.ndim = to;
                self.len = to;
                self.ptr = new_ptr;
            }
        }
    }

    fn index(&self, index: usize) -> &Self::S {
        match self.kind {
            Kind::One => {
                if index != self.len {
                    &self._noov
                } else {
                    unsafe { &*self.ptr }
                }
            }
            Kind::Many => unsafe { &*self.ptr.add(index) },
        }
    }

    fn index_mut(&mut self, index: usize) -> &mut Self::S {
        match self.kind {
            Kind::One => {
                if index != self.len {
                    let new_ptr = Self::new_many(self.ndim);
                    unsafe {
                        std::ptr::write(new_ptr.add(self.len), *self.ptr);
                        self.len = self.ndim;
                        self.kind = Kind::Many;
                        self.ptr = new_ptr;
                        &mut *new_ptr.add(index)
                    }
                } else {
                    unsafe { &mut *self.ptr }
                }
            }
            Kind::Many => unsafe { &mut *self.ptr.add(index) },
        }
    }
}

impl<A: Action<Single> + Copy> Drop for SeqAction<A> {
    fn drop(&mut self) {
        self.drop_inner();
    }
}

impl<A: Action<Single> + Copy> From<&[A]> for SeqAction<A> {
    fn from(value: &[A]) -> Self {
        let ptr = Self::new_many(value.len());
        for (i, a) in value.iter().enumerate() {
            unsafe {
                std::ptr::write(ptr.add(i), *a);
            }
        }
        Self {
            kind: Kind::Many,
            ptr,
            len: value.len(),
            ndim: value.len(),
            _noov: A::no_overwrite(),
        }
    }
}

impl<A: Action<Single> + Copy, const N: usize> From<[A; N]> for SeqAction<A> {
    fn from(value: [A; N]) -> Self {
        let ptr = Self::new_many(N);
        for (i, a) in value.iter().enumerate() {
            unsafe {
                std::ptr::write(ptr.add(i), *a);
            }
        }
        Self {
            kind: Kind::Many,
            ptr,
            len: N,
            ndim: N,
            _noov: A::no_overwrite(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{Hash, Hasher};

    use super::*;

    #[test]
    fn test_seq_actions_get() {
        let b = SeqAction::from([1, 2, 3]);
        assert_eq!(b.index(2), &3);
    }

    #[test]
    fn test_seq_actions_resize() {
        let mut a = SeqAction::from_single(1);
        a.resize_(3, 2);
        assert_eq!(a.index(1), &0);
        assert_eq!(a.index(2), &1);
        let mut b = SeqAction::from([1, 2, 3]);
        b.resize_(2, 0);
        assert_eq!(b.index(1), &2);
    }

    #[test]
    fn test_seq_actions_update() {
        let mut c = SeqAction::from([1, 2, 3]);
        *c.index_mut(2) = 4;
        assert_eq!(c.index(2), &4);
    }

    #[test]
    fn test_seq_actions_diff() {
        let a = SeqAction::from_single(1);
        let b = SeqAction::from_single(2);
        assert_eq!(a.diff(&b), 1);
        let c = SeqAction::from([1, 2, 3]);
        let d = SeqAction::from([1, 3, 4]);
        assert_eq!(c.diff(&d), 2);
    }

    #[test]
    fn test_seq_actions_overwrite() {
        let a = SeqAction::from_single(1);
        let b = SeqAction::from_single(2);
        let a = a.overwritten(&b);
        assert_eq!(a.index(0), &2);
        let c = SeqAction::from([1, 2, 3]);
        let d = SeqAction::from([1, 0, 4]);
        let c = c.overwritten(&d);
        assert_eq!(c.index(0), &1);
        assert_eq!(c.index(1), &2);
        assert_eq!(c.index(2), &4);
    }

    #[test]
    fn test_seq_actions_hash() {
        let mut a = SeqAction::from_single(1);
        a.resize_(3, 2);
        let b = SeqAction::from([0, 0, 1]);
        let mut hashera = std::collections::hash_map::DefaultHasher::new();
        let mut hasherb = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut hashera);
        b.hash(&mut hasherb);
        assert_eq!(hashera.finish(), hasherb.finish());
    }

    #[test]
    fn test_seq_actions_eq() {
        let mut a = SeqAction::from_single(1);
        a.resize_(3, 2);
        let b = SeqAction::from([0, 0, 1]);
        assert_eq!(a, b);
    }
}
