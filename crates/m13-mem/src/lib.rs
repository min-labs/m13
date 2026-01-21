#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::Mutex;
use zeroize::Zeroize;
use core::ops::{Deref, DerefMut};

// [FIX] Increased to 10KB to handle Kyber-1024 + Dilithium-87 Handshakes (~6.2KB)
pub const FRAME_SIZE: usize = 10240;

#[derive(Zeroize)]
pub struct Frame {
    pub data: [u8; FRAME_SIZE],
    pub len: usize,
}

impl Default for Frame {
    fn default() -> Self {
        Self {
            data: [0u8; FRAME_SIZE],
            len: 0,
        }
    }
}

pub struct SlabAllocator {
    pool: Mutex<Vec<Box<Frame>>>,
}

pub struct FrameLease {
    frame: Option<Box<Frame>>,
    allocator: Arc<SlabAllocator>,
}

impl SlabAllocator {
    pub fn new(capacity: usize) -> Arc<Self> {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            pool.push(Box::new(Frame::default()));
        }
        Arc::new(Self { pool: Mutex::new(pool) })
    }

    pub fn alloc(self: &Arc<Self>) -> Option<FrameLease> {
        let mut pool = self.pool.lock();
        if let Some(mut frame) = pool.pop() {
            frame.len = 0;
            Some(FrameLease { frame: Some(frame), allocator: self.clone() })
        } else {
            None
        }
    }

    fn release(&self, frame: Box<Frame>) {
        let mut pool = self.pool.lock();
        pool.push(frame);
    }
    
    pub fn available(&self) -> usize {
        self.pool.lock().len()
    }
}

impl Deref for FrameLease {
    type Target = Frame;
    fn deref(&self) -> &Self::Target { self.frame.as_ref().unwrap() }
}

impl DerefMut for FrameLease {
    fn deref_mut(&mut self) -> &mut Self::Target { self.frame.as_mut().unwrap() }
}

impl Drop for FrameLease {
    fn drop(&mut self) {
        if let Some(mut frame) = self.frame.take() {
            frame.zeroize();
            self.allocator.release(frame);
        }
    }
}
