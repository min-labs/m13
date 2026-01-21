#![no_std]
#![forbid(unsafe_code)]

extern crate alloc; // Required for Matrix

mod tables;
mod matrix;
pub use matrix::GfMatrix;
use tables::TABLES;
use zeroize::Zeroize;

/// A symbol in GF(2^8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Zeroize)]
#[repr(transparent)]
pub struct GfSymbol(pub u8);

impl GfSymbol {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    /// Add/Sub is XOR.
    #[inline(always)]
    pub fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    #[inline(always)]
    pub fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }

    /// Fast Multiplication (Tables).
    /// Use for Bulk Data (RLNC/RaptorQ).
    /// WARNING: Not constant time (Cache access pattern).
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 {
            return Self::ZERO;
        }
        // Indices are guaranteed valid by u8 range and 512-sized exp table.
        let idx = (TABLES.log[self.0 as usize] as usize) + (TABLES.log[rhs.0 as usize] as usize);
        Self(TABLES.exp[idx])
    }

    /// Constant-Time Multiplication (Russian Peasant).
    /// Use for Keys (AONT Mode B).
    /// Mitigates CWE-385.
    pub fn mul_safe(self, rhs: Self) -> Self {
        let mut p = 0u8;
        let mut a = self.0;
        let mut b = rhs.0;

        for _ in 0..8 {
            // Constant-time conditional XOR
            // mask = 0xFF if (b & 1) else 0x00
            let mask = (b as i8).wrapping_shl(7).wrapping_shr(7) as u8;
            p ^= a & mask;

            // xtime(a)
            let high_bit = (a & 0x80) != 0;
            a <<= 1;
            if high_bit {
                a ^= 0x1B; // Rijndael Poly (0x11B reduced)
            }
            b >>= 1;
        }
        Self(p)
    }

    /// Inversion (1/x).
    pub fn inv(self) -> Self {
        if self.0 == 0 { return Self::ZERO; }
        
        // log(1/a) = -log(a) = 255 - log(a)
        let log_a = TABLES.log[self.0 as usize] as usize;
        let idx = 255 - log_a;
        Self(TABLES.exp[idx])
    }
}

// Operator Overloads
impl core::ops::Add for GfSymbol {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { self.add(rhs) }
}
impl core::ops::Sub for GfSymbol {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { self.sub(rhs) }
}
impl core::ops::Mul for GfSymbol {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self { self.mul(rhs) }
}