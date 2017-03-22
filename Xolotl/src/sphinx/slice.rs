// Copyright 2016 Jeffrey Burdges.

//! Some slice utilities for the Sphinx header layout routines
//!
//! ...

use std::iter::{Iterator,IntoIterator,TrustedLen};  // ExactSizeIterator


/*
pub fn set_slice<T>(s: &mut [T], z: T) {
    for i in s.iter_mut() { *i = z; }
}
*/

/// Returns an initial segment of a `mut &[T]` replacing the inner
/// `&[T]` with the remainder.  In effect, this executes the command
/// `(return,heap) = heap.split_at(len)` without annoying the borrow
/// checker.  See http://stackoverflow.com/a/42162816/667457
pub fn reserve<'heap, T>(heap: &mut &'heap [T], len: usize) -> &'heap [T] {
    let tmp: &'heap [T] = ::std::mem::replace(&mut *heap, &[]);
    let (reserved, tmp) = tmp.split_at(len);
    *heap = tmp;
    reserved
}

/// A version of `reserve` for fixed length arrays.
macro_rules! reserve_fixed { ($heap:expr, $len:expr) => {
    array_ref![reserve($heap,$len),0,$len]
} }

/// Returns an initial segment of a `mut &mut [T]` replacing the inner
/// `&mut [T]` with the remainder.  In effect, this executes the command
/// `(return,heap) = heap.split_at_mut(len)` without annoying the borrow
/// checker.  See http://stackoverflow.com/a/42162816/667457
pub fn reserve_mut<'heap, T>(heap: &mut &'heap mut [T], len: usize) -> &'heap mut [T] {
    let tmp: &'heap mut [T] = ::std::mem::replace(&mut *heap, &mut []);
    let (reserved, tmp) = tmp.split_at_mut(len);
    *heap = tmp;
    reserved
}

/// A version of `reserve_mut` for fixed length arrays.
macro_rules! reserve_fixed_mut { ($heap:expr, $len:expr) => {
    array_mut_ref![reserve_mut($heap,$len),0,$len]
} }


/// Shift a slice `s` rightward by `shift` elements.  Does not zero
/// the initial segment created, but does return its bounds. 
/// Destroys the trailing `shift` elements of `s`.
pub fn pre_shift_right_slice<T: Copy>(s: &mut [T], shift: usize) -> ::std::ops::Range<usize> {
    let len = s.len();
    if len <= shift { return 0..len; }
    let mut i = s.len();
    let s = &mut s[..i];  // elide bounds checks; see Rust commit 6a7bc47
    while i > shift {
        i -= 1;
        s[i] = s[i-shift];
    }    // I dislike  for i in (target.len()-1 .. start-1).step_by(-1) { }
    0 .. ::std::cmp::min(shift,len)
}

/// Prepends an iterators contents to the slice `target`, shifting
/// `target` rightward.  Destroys the trailing `shift` elements of
/// `target`.
///
/// We sadly cannot require that `I::IntoIter: ExactSizeIterator` here
/// because `Chain` does not satisfy that, due to fears the length
/// might overflow.  See https://github.com/rust-lang/rust/issues/34433
/// Just requiring `TrustedLen` and asserting that `size_hint` gives
/// equal uper and lower bounds should be equevelent.
#[inline]
pub fn prepend_iterator<I>(target: &mut [I::Item], prepend: I) -> usize
  where I: IntoIterator, I::IntoIter: TrustedLen, I::Item: Copy
{
    let prepend = prepend.into_iter();

    // let start = prepend.len();
    let (start,end) = prepend.size_hint();
    assert_eq!(Some(start), end);

    let r = pre_shift_right_slice(target,start);

    let end = r.end;
    // target[r].copy_from_slice(prepend[r]);
    for (i,j) in target[r].iter_mut().zip(prepend) { *i = j; }
    end
}

/// Prepends the contents of a slice of slices `&[&[T]]` to the slice
/// `target`, shifting `target` rightward.  Destroys the trailing
/// `shift` elements of `target`.
///
/// As `FlatMap` does not `impl TrustedLen`, we do not do 
/// `prepend_to_slice(target, x.iter().flat_map(|y| *y).map(|z| *z) )`
/// As `Chain` does, we could use it with `prepend_iterator` and did so
/// in header.rs in f76aafd26776243d9f2282910b2d99c31b316797, but doing
/// so requires manually unrolling for a consistent type.
pub fn prepend_slice_of_slices<T: Copy>(target: &mut [T], prepend: &[&[T]]) -> usize
{
    let start = prepend.iter().map(|x| x.len()).sum();
    let r = pre_shift_right_slice(target,start);

    let end = r.end;
    let mut target = &mut target[r];
    for y in prepend.iter() {
        if target.len() < y.len() { break; }
        reserve_mut(&mut target,y.len()).copy_from_slice(y);
    }
    end
}



