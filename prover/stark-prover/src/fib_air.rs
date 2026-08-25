//! The Fibonacci test AIR from Plonky3.
//!
//! This file is a verbatim copy of the AIR and trace-generation part of
//! `p3-uni-stark 0.7.0-rc.1`, `tests/fib_air.rs` (the `FibonacciAir`, `FibonacciRow` and
//! `generate_trace_rows` items), so that the on-chain verifier targets exactly the constraint
//! system Plonky3 tests against.
//!
//! Plonky3 is Copyright (c) 2022 The Plonky3 Authors and is licensed under either of
//!
//! - the MIT License (<https://opensource.org/licenses/MIT>), or
//! - the Apache License, Version 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>),
//!
//! at your option. This copy is redistributed under those same terms; the rest of this crate
//! is GPL-3.0-only, which permits inclusion of MIT/Apache-2.0 licensed code with this notice.
//!
//! Constraint order (this order fixes the powers of `alpha` in the verifier's accumulator):
//!
//! 1. `is_first_row * (local.left - a)`
//! 2. `is_first_row * (local.right - b)`
//! 3. `is_transition * (local.right - next.left)`
//! 4. `is_transition * (local.left + local.right - next.right)`
//! 5. `is_last_row * (local.right - x)`

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

/// For testing the public values feature
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }

    fn num_public_values(&self) -> usize {
        3
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // All constraints are guarded by is_first_row / is_transition / is_last_row
        // (degree 1) applied to degree-1 expressions (trace vars minus public values),
        // giving a max constraint degree of 2.
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let pis = builder.public_values();

        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let local: &FibonacciRow<AB::Var> = main.current_slice().borrow();
        let next: &FibonacciRow<AB::Var> = main.next_slice().borrow();

        let mut when_first_row = builder.when_first_row();

        when_first_row.assert_eq(local.left, a);
        when_first_row.assert_eq(local.right, b);

        let mut when_transition = builder.when_transition();

        // a' <- b
        when_transition.assert_eq(local.right, next.left);

        // b' <- a + b
        when_transition.assert_eq(local.left + local.right, next.right);

        builder.when_last_row().assert_eq(local.right, x);
    }
}

pub fn generate_trace_rows<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibonacciRow::new(F::from_u64(a), F::from_u64(b));

    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }

    trace
}

pub const NUM_FIBONACCI_COLS: usize = 2;

pub struct FibonacciRow<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> Self {
        Self { left, right }
    }
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// End of the copied Plonky3 code. The helper below is QuantaProof's own.

/// The public values `[a, b, x]` for a trace of `n` rows started from `(a, b)`: `x` is the
/// `right` cell of the last row, exactly what the last-row constraint checks.
pub fn public_values<F: PrimeField64>(trace: &RowMajorMatrix<F>, a: u64, b: u64) -> [F; 3] {
    let last = trace
        .values
        .len()
        .checked_sub(1)
        .expect("trace must have at least one row");
    [F::from_u64(a), F::from_u64(b), trace.values[last]]
}
