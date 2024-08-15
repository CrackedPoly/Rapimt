use std::{cmp::min, fmt::Binary, ops::Range};

use bitvec::prelude::*;

use rapimt_core::{r#match::MaskedValue, HeaderBitOrder, HeaderBitStore, HEADERSTORENUM};

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct Segment {
    pub mv: MaskedValue,
    pub len: usize,
}

impl Binary for Segment {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..self.mv.mask.len() {
            match (self.mv.value[i], self.mv.mask[i]) {
                (true, true) => write!(f, "1")?,
                (false, true) => write!(f, "0")?,
                _ => write!(f, "*")?,
            }
        }
        write!(f, "/{}", self.len)
    }
}

impl Segment {
    /// this is a prefix of rhs
    pub fn is_prefix_of(&self, rhs: Segment) -> bool {
        let len = self.len;
        let rhs_len = rhs.len;
        if len > rhs_len || self.mv.mask[0..len] != rhs.mv.mask[0..len] {
            false
        } else {
            // mask equals, check valid value bits
            let mut bits = BitArray::<[HeaderBitStore; HEADERSTORENUM], HeaderBitOrder>::ZERO;
            bits[0..len].copy_from_bitslice(&rhs.mv.value[0..len]);
            bits[0..len] ^= self.mv.value;
            bits[0..len] &= self.mv.mask;
            bits[0..len].not_any()
        }
    }

    pub fn is_superset_of(&self, rhs: Segment) -> bool {
        let mut bits = BitArray::<[HeaderBitStore; HEADERSTORENUM], HeaderBitOrder>::ZERO;
        let len = self.len;
        let rhs_len = rhs.len;
        bits[0..len].copy_from_bitslice(&self.mv.mask[0..len]);
        if len > rhs_len && bits[rhs_len..len].any() {
            // mask may exceed rhs.mask (11*1 v.s. 11)
            false
        } else {
            // we only need to consider [0..len]
            bits[0..len] &= &rhs.mv.mask[0..len];
            if bits[0..len] != self.mv.mask[0..len] {
                false
            } else {
                // mask covers (mask has more 0 than rhs.mask), check valid value equals
                bits[0..len].copy_from_bitslice(&rhs.mv.value[0..len]);
                bits[0..len] ^= self.mv.value;
                bits[0..len] &= self.mv.mask;
                bits[0..len].not_any()
            }
        }
    }

    #[inline]
    pub fn intersect(&self, rhs: Segment) -> Option<Segment> {
        if self.intersect_any(rhs) {
            let mask = self.mv.mask | rhs.mv.mask;
            let value = self.mv.value | rhs.mv.value;
            Some(Segment {
                mv: MaskedValue { value, mask },
                len: min(self.len, rhs.len),
            })
        } else {
            None
        }
    }

    #[inline]
    pub fn intersect_any(&self, rhs: Segment) -> bool {
        let common_mask = self.mv.mask & rhs.mv.mask;
        self.mv.value & common_mask == rhs.mv.value & common_mask
    }

    #[inline]
    pub fn range(&self, range: Range<usize>) -> Segment {
        let mut value = BitArray::ZERO;
        let mut mask = BitArray::ZERO;
        value[0..range.len()].copy_from_bitslice(&self.mv.value[range.clone()]);
        mask[0..range.len()].copy_from_bitslice(&self.mv.mask[range.clone()]);
        Segment {
            mv: MaskedValue { value, mask },
            len: range.len(),
        }
    }

    #[inline]
    pub fn shift_left(&mut self, rhs: usize) {
        self.mv.value.shift_left(rhs);
        self.mv.mask.shift_left(rhs);
        self.len -= rhs;
    }

    #[inline]
    pub fn prepend(&mut self, seg: Segment) {
        let len = seg.len;
        self.mv.value.shift_right(len);
        self.mv.mask.shift_right(len);
        self.mv.value[0..len].copy_from_bitslice(&seg.mv.value[0..len]);
        self.mv.mask[0..len].copy_from_bitslice(&seg.mv.mask[0..len]);
        self.len += len;
    }
}

// Segmentized is a scanner that can scan V (which can represent an array of ternary digits).
pub trait Segmentized<V>: Sized {
    // get the length of the original segment
    fn len(&self) -> usize;
    // get the current position of the scanner
    fn current_pos(&self) -> usize;
    // get the current segment
    fn current(&self) -> Segment;
    // get the next segment
    fn next(&self) -> Segment;
    // get the longest prefix match of the current segment against the given prefix
    fn lpm(&mut self, prefix: Segment) -> Segment {
        while self.has_next() && self.next().is_prefix_of(prefix) {
            self.proceed(1);
        }
        self.current()
    }

    // is the current segment empty
    fn is_empty(&self) -> bool {
        self.current_pos() == 0
    }
    // does the current segment have a next pair
    fn has_next(&self) -> bool;
    // get the next pair (value, mask)
    fn next_pair(&self) -> (bool, bool);

    // proceed the scanner by steps
    fn proceed(&mut self, steps: usize);
    // strip the prefix before the index, and return the remaining segment as a segmentizer
    fn pstrip_at(&self, index: usize) -> Option<Self>;
    // cut the remaining segment as a new segment
    fn cut(&self) -> Option<Self> {
        if !self.has_next() {
            None
        } else {
            let start = self.current_pos();
            self.pstrip_at(start)
        }
    }
    // assert the next ternary bit must cover the asserted value and mask, if so,
    fn assert_next(&self, assert_value: bool, assert_mask: bool) -> Option<Self>;
}

pub struct Segmentizer {
    orig: Segment,
    pos: usize,
}

impl Binary for Segmentizer {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "origin: ")?;
        self.orig.fmt(f)?;
        write!(f, ", current pos: {}", self.pos)
    }
}

impl From<Segment> for Segmentizer {
    #[inline]
    fn from(seg: Segment) -> Self {
        Segmentizer { orig: seg, pos: 0 }
    }
}

impl From<MaskedValue> for Segmentizer {
    #[inline]
    fn from(mv: MaskedValue) -> Self {
        Segmentizer {
            orig: Segment {
                mv,
                len: mv.mask.len(),
            },
            pos: 0,
        }
    }
}

impl<V> Segmentized<V> for Segmentizer {
    #[inline]
    fn len(&self) -> usize {
        self.orig.len
    }

    #[inline]
    fn current_pos(&self) -> usize {
        self.pos
    }

    #[inline]
    fn has_next(&self) -> bool {
        self.pos < self.orig.len
    }

    #[inline]
    fn next_pair(&self) -> (bool, bool) {
        (self.orig.mv.value[self.pos], self.orig.mv.mask[self.pos])
    }

    #[inline]
    fn current(&self) -> Segment {
        self.orig.range(0..self.pos)
    }

    #[inline]
    fn next(&self) -> Segment {
        self.orig.range(0..self.pos + 1)
    }

    #[inline]
    fn proceed(&mut self, steps: usize) {
        self.pos = min(self.pos + steps, self.orig.len);
    }

    fn pstrip_at(&self, index: usize) -> Option<Self> {
        let len = self.orig.len;
        if index >= len {
            None
        } else {
            Some(Segmentizer {
                orig: self.orig.range(index..len),
                pos: 0,
            })
        }
    }

    fn assert_next(&self, assert_value: bool, assert_mask: bool) -> Option<Self> {
        if !Segmentized::<V>::has_next(self) {
            None
        } else {
            let (value, mask) = Segmentized::<V>::next_pair(self);
            if mask && (!assert_mask || value != assert_value) {
                None
            } else {
                let start = Segmentized::<V>::current_pos(self);
                let mut seg = Segmentized::<V>::pstrip_at(self, start)?;
                unsafe {
                    seg.orig.mv.value.as_mut_bitptr().write(assert_value);
                    seg.orig.mv.mask.as_mut_bitptr().write(assert_mask);
                    Some(seg)
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn from_str(s: &str) -> Segment {
        let mut value = BitArray::<[HeaderBitStore; HEADERSTORENUM], HeaderBitOrder>::ZERO;
        let mut mask = BitArray::<[HeaderBitStore; HEADERSTORENUM], HeaderBitOrder>::ZERO;
        let mut i = 0;
        s.chars().for_each(|c| {
            match c {
                '0' => {
                    mask.set(i, true);
                }
                '1' => {
                    mask.set(i, true);
                    value.set(i, true);
                }
                _ => {}
            }
            i += 1;
        });
        Segment {
            mv: MaskedValue { value, mask },
            len: s.len(),
        }
    }

    mod segment {
        use super::*;

        fn str_is_prefix_of(x: &str, y: &str) -> bool {
            let x_seg = from_str(x);
            let y_seg = from_str(y);
            x_seg.is_prefix_of(y_seg)
        }

        #[test]
        fn test_is_prefix_of() {
            assert!(str_is_prefix_of("1*", "1*10"));
            assert!(!str_is_prefix_of("1*0", "1*10"));
        }

        fn str_is_superset_of(x: &str, y: &str) -> bool {
            let x_seg = from_str(x);
            let y_seg = from_str(y);
            x_seg.is_superset_of(y_seg)
        }

        #[test]
        fn test_is_superset_of() {
            assert!(str_is_superset_of("111*", "1111"));
            assert!(str_is_superset_of("11", "1111"));
            assert!(!str_is_superset_of("1*10", "1111"));
        }

        fn str_intersect(x: &str, y: &str) -> Option<Segment> {
            let x_seg = from_str(x);
            let y_seg = from_str(y);
            x_seg.intersect(y_seg)
        }

        #[test]
        fn test_intersect() {
            assert!(str_intersect("1*10", "1*11").is_none());
            assert_eq!(str_intersect("0*1*0", "***00").unwrap(), from_str("0*100"));
            assert_eq!(str_intersect("0*1**", "***0").unwrap(), from_str("0*10"));
        }
    }

    mod segmentizer {
        use super::*;

        #[test]
        fn test_cut() {
            let str = "1*0*1";
            let seg = from_str(str);
            let mut seger = Segmentizer::from(seg);
            Segmentized::<u32>::proceed(&mut seger, 2);
            assert_eq!(seger.pos, 2);
            let cut = Segmentized::<u32>::cut(&seger).unwrap();
            assert_eq!(cut.orig.len, 3);
            assert_eq!(cut.pos, 0);
        }

        #[test]
        fn test_assert_next() {
            let str = "1*0*1";
            let seg = from_str(str);
            let mut seger = Segmentizer::from(seg);
            Segmentized::<u32>::proceed(&mut seger, 2);
            let assert_00 = Segmentized::<u32>::assert_next(&seger, false, false);
            assert!(assert_00.is_none());
            let assert_01 = Segmentized::<u32>::assert_next(&seger, false, true).unwrap();
            assert_eq!(assert_01.orig.len, 3);
            assert_eq!(assert_01.pos, 0);
            assert!(!assert_01.orig.mv.value[0]);
            assert!(assert_01.orig.mv.mask[0]);
            Segmentized::<u32>::proceed(&mut seger, 1);
            let assert_00 = Segmentized::<u32>::assert_next(&seger, false, false).unwrap();
            assert_eq!(assert_00.orig.len, 2);
            assert_eq!(assert_00.pos, 0);
            assert!(!assert_00.orig.mv.value[0]);
            assert!(!assert_00.orig.mv.mask[0]);
            let assert_01 = Segmentized::<u32>::assert_next(&seger, false, true).unwrap();
            assert_eq!(assert_01.orig.len, 2);
            assert_eq!(assert_01.pos, 0);
            assert!(!assert_01.orig.mv.value[0]);
            assert!(assert_01.orig.mv.mask[0]);
        }

        #[test]
        fn test_lpm() {
            let str = "1*0*1";
            let seg = from_str(str);
            let mut seger = Segmentizer::from(seg);
            let _ = Segmentized::<u32>::lpm(&mut seger, from_str("1*"));
            assert_eq!(seger.pos, 2);
        }
    }
}
