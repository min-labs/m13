#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result}; // Removed M13Header dependency here
use m13_math::{GfMatrix, GfSymbol};
use m13_cipher::generate_coefficients;

/// The Fountain Decoder.
/// Collects "droplets" until the "bucket" is full (Rank == K).
pub struct FountainDecoder {
    block_size_k: usize,
    symbol_size: usize,
    gen_id: u16,
    
    // The Equation Matrix (A in Ax = b)
    matrix: GfMatrix,
    // The Received Symbols (b in Ax = b)
    symbols: GfMatrix, 
    
    // Tracks current fill level
    count: usize,
    // Map of received Symbol IDs to avoid duplicates
    seen_symbols: Vec<u32>,
    // State tracking
    is_solved: bool,
}

impl FountainDecoder {
    pub fn new(block_size_k: usize, symbol_size: usize, gen_id: u16) -> Self {
        // OVER-PROVISIONING: Allow K + 8 symbols for overhead
        let capacity = block_size_k + 8;
        
        Self {
            block_size_k,
            symbol_size,
            gen_id,
            matrix: GfMatrix::new(capacity, block_size_k),
            symbols: GfMatrix::new(capacity, symbol_size),
            count: 0,
            seen_symbols: Vec::new(),
            is_solved: false,
        }
    }

    /// KERNEL API COMPATIBILITY LAYER
    /// Ingests a symbol and attempts to solve immediately if possible.
    pub fn receive_symbol(&mut self, symbol_id: u32, payload: &[u8]) -> M13Result<Option<Vec<u8>>> {
        // 1. Absorb
        self.absorb(symbol_id, self.gen_id, payload)?;

        // 2. Check if Solvable
        if self.is_decodable() && !self.is_solved {
            // 3. Attempt Solve
            match self.decode() {
                Ok(data) => {
                    self.is_solved = true;
                    Ok(Some(data))
                },
                // If singular (linear dependency), we wait for more symbols
                Err(M13Error::CryptoFailure) => Ok(None), 
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    /// Absorb a packet (Internal Logic)
    /// Updated signature to take raw ID/GenID instead of Header struct
    fn absorb(&mut self, symbol_id: u32, gen_id: u16, payload: &[u8]) -> M13Result<()> {
        if gen_id != self.gen_id { return Err(M13Error::WireFormatError); }
        if self.seen_symbols.contains(&symbol_id) { return Ok(()); } 
        if self.count >= self.matrix.rows { return Ok(()); } 

        // 1. Construct the Equation Vector (Row)
        let row_coeffs = if (symbol_id as usize) < self.block_size_k {
            // Systematic: Identity Vector (e.g., [0, 1, 0...])
            let mut r = alloc::vec![GfSymbol::ZERO; self.block_size_k];
            r[symbol_id as usize] = GfSymbol::ONE;
            r
        } else {
            // Coded: Generator coefficients
            let raw = generate_coefficients(symbol_id, self.gen_id, self.block_size_k);
            raw.iter().map(|&b| GfSymbol(b)).collect()
        };

        // 2. Insert into Matrix
        let slot = self.count;
        for c in 0..self.block_size_k {
            self.matrix.set(slot, c, row_coeffs[c]);
        }
        for c in 0..self.symbol_size {
            let val = if c < payload.len() { payload[c] } else { 0 };
            self.symbols.set(slot, c, GfSymbol(val));
        }

        self.count += 1;
        self.seen_symbols.push(symbol_id);
        
        Ok(())
    }

    pub fn is_decodable(&self) -> bool {
        self.count >= self.block_size_k
    }

    /// Solve the system. Returns the original source data.
    pub fn decode(&self) -> M13Result<Vec<u8>> {
        if !self.is_decodable() { return Err(M13Error::InvalidState); }

        let rows = self.count;
        let cols = self.block_size_k; 
        
        let mut a = self.matrix.clone();
        let mut b = self.symbols.clone();

        let mut pivot_row = 0;
        
        // Gaussian Elimination
        for col_idx in 0..cols {
            if pivot_row >= rows { break; }

            // Find Pivot
            let mut curr = pivot_row;
            while curr < rows && a.get(curr, col_idx) == Some(GfSymbol::ZERO) {
                curr += 1;
            }
            
            if curr == rows { 
                // Singular matrix (Dependent rows)
                return Err(M13Error::CryptoFailure); 
            }

            // Swap Rows
            if curr != pivot_row {
                for c in 0..cols {
                    let temp = a.get(pivot_row, c).unwrap();
                    a.set(pivot_row, c, a.get(curr, c).unwrap());
                    a.set(curr, c, temp);
                }
                for c in 0..self.symbol_size {
                    let temp = b.get(pivot_row, c).unwrap();
                    b.set(pivot_row, c, b.get(curr, c).unwrap());
                    b.set(curr, c, temp);
                }
            }

            // Normalize Pivot
            let p_val = a.get(pivot_row, col_idx).unwrap();
            let inv = p_val.inv();
            
            for c in col_idx..cols {
                a.set(pivot_row, c, a.get(pivot_row, c).unwrap() * inv);
            }
            for c in 0..self.symbol_size {
                b.set(pivot_row, c, b.get(pivot_row, c).unwrap() * inv);
            }

            // Eliminate
            for r in 0..rows {
                if r != pivot_row {
                    let factor = a.get(r, col_idx).unwrap();
                    if factor != GfSymbol::ZERO {
                        for c in col_idx..cols {
                            let val = a.get(r, c).unwrap() - (factor * a.get(pivot_row, c).unwrap());
                            a.set(r, c, val);
                        }
                        for c in 0..self.symbol_size {
                            let val = b.get(r, c).unwrap() - (factor * b.get(pivot_row, c).unwrap());
                            b.set(r, c, val);
                        }
                    }
                }
            }
            pivot_row += 1;
        }

        // Extract Result
        let mut result = Vec::with_capacity(cols * self.symbol_size);
        for r in 0..cols {
            for c in 0..self.symbol_size {
                result.push(b.get(r, c).unwrap().0);
            }
        }
        Ok(result)
    }
}