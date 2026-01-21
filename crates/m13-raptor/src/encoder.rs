#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result, M13Header, PacketType, M13_MAGIC};
use m13_math::{GfSymbol};
use m13_cipher::generate_coefficients;

/// Appendix D.1: Cap block size to prevent CPU exhaustion.
pub const MAX_BLOCK_SYMBOLS: usize = 256; 

/// The Fountain Encoder.
/// "Pours" symbols into the channel.
pub struct FountainEncoder {
    source_data: Vec<u8>,
    symbol_size: usize,
    block_size_k: usize,
    gen_id: u16,
    cursor: u32, // The current Symbol ID being generated
}

impl FountainEncoder {
    pub fn new(data: &[u8], symbol_size: usize, gen_id: u16) -> M13Result<Self> {
        if symbol_size == 0 { return Err(M13Error::InvalidState); }
        
        // Calculate K (Round up)
        let block_size_k = (data.len() + symbol_size - 1) / symbol_size;
        
        if block_size_k > MAX_BLOCK_SYMBOLS {
             return Err(M13Error::InvalidState); 
        }

        Ok(Self {
            source_data: data.to_vec(),
            symbol_size,
            block_size_k,
            gen_id,
            cursor: 0,
        })
    }

    /// Produce the next packet in the stream.
    /// 0..K: Systematic Symbols (The data itself).
    /// K..∞: Repair Symbols (Linear Combinations).
    pub fn next_packet(&mut self) -> (M13Header, Vec<u8>) {
        let sym_id = self.cursor;
        self.cursor += 1;

        let payload = if (sym_id as usize) < self.block_size_k {
            // SYSTEMATIC PHASE: Send raw slice
            let start = (sym_id as usize) * self.symbol_size;
            let end = core::cmp::min(start + self.symbol_size, self.source_data.len());
            
            let mut chunk = self.source_data[start..end].to_vec();
            // Padding if last symbol is partial
            if chunk.len() < self.symbol_size {
                chunk.resize(self.symbol_size, 0);
            }
            chunk
        } else {
            // REPAIR PHASE: Random Linear Combination
            // Generate coefficients based on Symbol ID (Seed)
            let coeffs_raw = generate_coefficients(sym_id, self.gen_id, self.block_size_k);
            
            let mut result = alloc::vec![GfSymbol::ZERO; self.symbol_size];

            for i in 0..self.block_size_k {
                let coeff = GfSymbol(coeffs_raw[i]);
                if coeff == GfSymbol::ZERO { continue; }

                // Get source symbol i
                let start = i * self.symbol_size;
                let end = core::cmp::min(start + self.symbol_size, self.source_data.len());
                
                // Safe slice access with zero padding logic implicit
                for (j, &byte) in self.source_data[start..end].iter().enumerate() {
                    result[j] = result[j] + (coeff * GfSymbol(byte));
                }
            }
            result.iter().map(|s| s.0).collect()
        };

        let header = M13Header {
            magic: M13_MAGIC,
            version: 1,
            packet_type: if (sym_id as usize) < self.block_size_k { PacketType::Data } else { PacketType::Coded },
            gen_id: self.gen_id,
            symbol_id: sym_id,
            payload_len: payload.len() as u16,
            recoder_rank: 0,
            reserved: 0,
            auth_tag: [0u8; 16], // Filled by Cipher later
        };

        (header, payload)
    }

    pub fn num_source_symbols(&self) -> usize {
        self.block_size_k
    }
}