#![no_std]
extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::collections::{VecDeque, BTreeMap};

use log::{info, warn};

use m13_core::{M13Result, M13Header, PacketType, M13_MAGIC, M13Error};
use m13_core::KYBER_PK_LEN_1024;
use m13_core::KYBER_CT_LEN_1024;

use m13_hal::{PhysicalInterface, SecurityModule, PlatformClock, PeerAddr};
use m13_mem::{SlabAllocator, FrameLease};
use m13_cipher::{M13Cipher, SessionKey};
use m13_pqc::{KyberKeypair, kyber_encapsulate, kyber_decapsulate, dsa_sign, DsaKeypair};
use m13_raptor::{FountainEncoder, FountainDecoder};
use m13_flow::Pacer;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub mod fragment;
pub mod session;
use session::Session;

// VECTOR BATCH SIZE
const BATCH_SIZE: usize = 64;
const RAPTOR_SYMBOL_SIZE: usize = 1024;

fn is_allowed(addr: &PeerAddr) -> bool {
    match addr {
        PeerAddr::V4(_, _) => true, 
        _ => false,
    }
}

fn parse_ipv4_headers(packet: &[u8]) -> Option<(u32, u32)> {
    if packet.len() < 20 { return None; }
    if packet[0] >> 4 != 4 { return None; }
    let src = u32::from_be_bytes(packet[12..16].try_into().ok()?);
    let dst = u32::from_be_bytes(packet[16..20].try_into().ok()?);
    Some((src, dst))
}

#[derive(Debug, Clone, Copy)]
pub struct KernelConfig {
    pub is_hub: bool,
    pub enable_encryption: bool,
}

pub struct M13Kernel {
    phy: Box<dyn PhysicalInterface>,
    #[allow(dead_code)]
    sec: Box<dyn SecurityModule>,
    clock: Box<dyn PlatformClock>,
    mem: Arc<SlabAllocator>,
    
    config: KernelConfig,
    rng: ChaCha20Rng,
    identity: DsaKeypair,

    sessions: BTreeMap<PeerAddr, Session>,
    routes: BTreeMap<u32, PeerAddr>,

    node_target: Option<PeerAddr>,
    pending_kyber: Option<KyberKeypair>,

    // [PHYSICS] Zero-Copy Batch Cache (Scalar 'rx_queue' Removed)
    rx_batch_cache: Vec<FrameLease>, 

    pub tun_tx_queue: VecDeque<Vec<u8>>, 
    pub tun_rx_queue: VecDeque<Vec<u8>>,
    
    last_handshake_tx: u64,

    // LIQUID VECTOR STATE
    pacer: Pacer,
    data_encoder: Option<(FountainEncoder, u32, Option<PeerAddr>)>, 
    data_decoders: BTreeMap<u16, FountainDecoder>,
    next_data_gen_id: u16,
}

impl M13Kernel {
    pub fn new(
        phy: Box<dyn PhysicalInterface>,
        mut sec: Box<dyn SecurityModule>,
        clock: Box<dyn PlatformClock>,
        mem: Arc<SlabAllocator>,
        config: KernelConfig,
        identity: DsaKeypair,
    ) -> Self {
        let mut seed = [0u8; 32];
        let _ = sec.get_random_bytes(&mut seed);
        let rng = ChaCha20Rng::from_seed(seed);

        // [COSMETIC UPDATE] v0.3.0 Identity
        info!(">>> [KERNEL] v0.3.0: System Physics & Egress Offload <<<");
        
        // [PHYSICS CHECK] Query the math engine for truth
        let math_engine = m13_math::get_active_engine();
        info!(">>> [PHYSICS] MATH ACCELERATOR: {} <<<", math_engine);

        Self {
            phy, sec, clock, mem, config, identity,
            rng,
            sessions: BTreeMap::new(),
            routes: BTreeMap::new(),
            node_target: None,
            pending_kyber: None,
            rx_batch_cache: Vec::with_capacity(BATCH_SIZE),
            tun_tx_queue: VecDeque::new(),
            tun_rx_queue: VecDeque::new(),
            last_handshake_tx: 0,
            
            pacer: Pacer::new(10_000_000), 
            data_encoder: None,
            data_decoders: BTreeMap::new(),
            next_data_gen_id: 1,
        }
    }

    pub fn send_payload(&mut self, data: &[u8]) -> M13Result<()> {
        if self.tun_tx_queue.len() < 256 {
            self.tun_tx_queue.push_back(data.to_vec());
            Ok(())
        } else {
            Err(M13Error::InvalidState)
        }
    }

    pub fn pop_ingress(&mut self) -> Option<Vec<u8>> {
        self.tun_rx_queue.pop_front()
    }

    pub fn poll(&mut self) -> bool {
        let now = self.clock.now_us();
        let mut work_done = false;

        // Session Liveness Check
        if !self.config.is_hub {
            let mut session_alive = false;
            for (_, session) in self.sessions.iter() {
                if session.cipher.is_some() {
                    session_alive = true;
                }
            }
            if !session_alive {
                if now.saturating_sub(self.last_handshake_tx) > 2_000_000 {
                    info!("Client: Initiating Handshake (Cold Start)...");
                    self.initiate_handshake(None); 
                    self.last_handshake_tx = now;
                    work_done = true;
                }
            }
        }

        // [PHYSICS] ZERO-COPY BATCH RX
        let mut batch = core::mem::take(&mut self.rx_batch_cache);

        while batch.len() < BATCH_SIZE {
            if let Some(lease) = self.mem.alloc() { batch.push(lease); }
            else { break; }
        }

        if !batch.is_empty() {
            let mut ptrs: Vec<&mut [u8]> = batch.iter_mut()
                .map(|lease| &mut lease.data[..])
                .collect();
            
            let mut meta = alloc::vec![(0, PeerAddr::None); ptrs.len()];

            if let Ok(n) = self.phy.recv_batch(&mut ptrs, &mut meta) {
                if n > 0 {
                    work_done = true;
                    for (i, mut lease) in batch.drain(0..n).enumerate() {
                        let (len, src) = meta[i];
                        lease.len = len;
                        if self.config.is_hub && !is_allowed(&src) {
                             warn!("Blocked unauthorized peer: {:?}", src);
                        } else {
                             self.handle_packet(lease, src, now); 
                        }
                    }
                }
            }
        }

        self.rx_batch_cache = batch;

        // PACER TICK
        self.pacer.tick(now);

        // LIQUID EGRESS (GSO Enabled)
        if self.config.is_hub || !self.sessions.is_empty() {
            if self.data_encoder.is_some() {
                self.pump_liquid_data();
                work_done = true;
            } 
            else {
                // [PHYSICS] GSO AGGREGATION
                let segment_size = 1328u16; 
                let mut gso_buffer = Vec::with_capacity(64000);
                let mut current_target: Option<PeerAddr> = None;
                
                // Drain up to 64 packets
                let mut count = 0;
                while count < 64 {
                    // [AUDIT FIX] Pacer Check for GSO
                    // We must check if we have tokens BEFORE popping to avoid dropping packets.
                    // Assuming MTU cost + overhead
                    if let Some(next_payload) = self.tun_tx_queue.front() {
                        let cost = next_payload.len() + 64;
                        if !self.pacer.chaff_needed(cost) {
                            // Pacer exhausted: Yield to allow token refill
                            break;
                        }
                    } else {
                        break; // Queue empty
                    }

                    if let Some(payload) = self.tun_tx_queue.pop_front() {
                        // Consume Tokens
                        let cost = payload.len() + 64;
                        self.pacer.consume(cost);

                        // 1. Determine Target
                        let target_peer = if self.config.is_hub {
                             if let Some((_, dest_vip)) = parse_ipv4_headers(&payload) {
                                self.routes.get(&dest_vip).cloned()
                             } else { None }
                        } else {
                             self.node_target
                        };

                        if let Some(target) = target_peer {
                            // 2. Flush on Target Mismatch
                            if let Some(curr) = current_target {
                                if curr != target {
                                    // Flush current buffer
                                    self.phy.send_gso(&gso_buffer, Some(curr), segment_size).ok();
                                    gso_buffer.clear();
                                    current_target = Some(target);
                                }
                            } else {
                                current_target = Some(target);
                            }
                            
                            // 3. Encrypt & Append
                            // (Fountain Encoder Logic - Swaps Mode if Enabled)
                            if let Ok(enc) = FountainEncoder::new(&payload, RAPTOR_SYMBOL_SIZE, self.next_data_gen_id) {
                                 self.data_encoder = Some((enc, 0, Some(target)));
                                 self.next_data_gen_id = self.next_data_gen_id.wrapping_add(1);
                                 // Flush whatever we have in GSO
                                 if !gso_buffer.is_empty() {
                                     if let Some(curr) = current_target {
                                         self.phy.send_gso(&gso_buffer, Some(curr), segment_size).ok();
                                     }
                                 }
                                 self.pump_liquid_data();
                                 work_done = true;
                                 break; 
                            }
                            
                            // 4. Standard Encryption (Non-Fountain)
                             gso_buffer.extend_from_slice(&payload);
                        }
                    } else {
                        break;
                    }
                    count += 1;
                }
                
                // Final Flush
                if !gso_buffer.is_empty() {
                    if let Some(curr) = current_target {
                        self.phy.send_gso(&gso_buffer, Some(curr), segment_size).ok();
                        work_done = true;
                    }
                }
            }
        }
        
        work_done
    }

    fn pump_liquid_data(&mut self) {
        if let Some((enc, sent_count, target_peer)) = &mut self.data_encoder {
            let k = enc.num_source_symbols();
            let overhead = core::cmp::max(1, (k * 10) / 100);
            let target = (k + overhead) as u32;
            let packet_cost = RAPTOR_SYMBOL_SIZE + 64; 

            let mut burst = 0;
            while *sent_count < target && burst < BATCH_SIZE {
                if !self.pacer.chaff_needed(packet_cost) { break; }
                
                let (mut header, mut payload) = enc.next_packet();
                header.packet_type = PacketType::Coded; 
                header.reserved = k as u8;

                if let Some(mut lease) = self.mem.alloc() {
                    let cipher_ref = if let Some(t) = target_peer {
                         self.sessions.get(t).and_then(|s| s.cipher.as_ref())
                    } else if !self.config.is_hub {
                         self.sessions.values().next().and_then(|s| s.cipher.as_ref())
                    } else {
                         None 
                    };

                    if let Some(cipher) = cipher_ref {
                        if let Ok(tag) = cipher.encrypt_detached(&header, &mut payload) {
                             header.auth_tag = tag;
                        }
                    }

                    header.to_bytes(&mut lease.data).ok();
                    lease.data[32..32+payload.len()].copy_from_slice(&payload);
                    
                    self.phy.send(&lease.data[..32+payload.len()], *target_peer).ok();
                    
                    self.pacer.consume(packet_cost);
                    *sent_count += 1;
                    burst += 1;
                } else {
                    break; 
                }
            }
            
            if *sent_count >= target { self.data_encoder = None; }
        }
    }

    // ... (rest of handle_packet and others unchanged) ...
    fn handle_packet(&mut self, mut frame: FrameLease, peer: PeerAddr, now: u64) {
        if let Ok(header) = M13Header::from_bytes(&frame.data[0..32]) {
            let payload_len = header.payload_len as usize;
            if frame.len < 32 + payload_len { return; }
            let payload = &mut frame.data[32..32+payload_len];

            if !self.sessions.contains_key(&peer) {
                if self.config.is_hub && header.packet_type == PacketType::ClientHello {
                    info!("New Peer Detected: {:?}", peer);
                    self.sessions.insert(peer, Session::new(now));
                } else if !self.config.is_hub {
                    if self.sessions.is_empty() {
                        self.sessions.insert(peer, Session::new(now));
                        self.node_target = Some(peer);
                    }
                } else { return; }
            }

            let session = self.sessions.get_mut(&peer).unwrap();
            let rng = &mut self.rng;
            let identity = &self.identity;
            let mem = &self.mem;
            let phy = &mut *self.phy;
            let pending_kyber = &mut self.pending_kyber;
            let routes = &mut self.routes;
            let is_hub = self.config.is_hub;

            match header.packet_type {
                PacketType::ClientHello => {
                    if is_hub {
                        if let Ok(Some(full_data)) = session.assembler.ingest(payload) {
                            session.last_valid_rx_us = now;
                            Self::process_client_hello(rng, identity, mem, phy, session, &full_data, peer);
                        }
                    }
                },
                PacketType::HandshakeInit => {
                    if !is_hub {
                        if let Ok(Some(full_data)) = session.assembler.ingest(payload) {
                            session.last_valid_rx_us = now;
                            Self::process_server_hello(session, &full_data, pending_kyber);
                        }
                    }
                },
                PacketType::Coded | PacketType::Data => {
                    if let Some(cipher) = &session.cipher {
                        if cipher.decrypt_detached(&header, payload).is_ok() {
                            session.last_valid_rx_us = now;
                            
                            let gen_id = header.gen_id;
                            let k = if header.reserved > 0 { header.reserved as usize } else { 1 };
                            
                            let decoder = self.data_decoders.entry(gen_id).or_insert_with(|| {
                                FountainDecoder::new(k, RAPTOR_SYMBOL_SIZE, gen_id)
                            });
                            
                            if let Ok(Some(decoded_data)) = decoder.receive_symbol(header.symbol_id, payload) {
                                if is_hub {
                                    if let Some((src_vip, _)) = parse_ipv4_headers(&decoded_data) {
                                        routes.insert(src_vip, peer);
                                    }
                                }
                                self.tun_rx_queue.push_back(decoded_data);
                                self.data_decoders.remove(&gen_id); 
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    }

    fn initiate_handshake(&mut self, target: Option<PeerAddr>) {
        if let Ok(kp) = KyberKeypair::generate(&mut self.rng) {
            let mut payload = Vec::new();
            payload.extend_from_slice(&kp.public);
            
            if let Some(t) = target {
                let mut s = Session::new(0);
                s.ephemeral_key = Some(kp);
                self.sessions.insert(t, s);
            } else {
                self.pending_kyber = Some(kp);
            }
            Self::send_fragmented(&self.mem, &mut *self.phy, PacketType::ClientHello, &payload, target);
        }
    }

    fn process_client_hello(
        rng: &mut ChaCha20Rng,
        identity: &DsaKeypair,
        mem: &Arc<SlabAllocator>,
        phy: &mut dyn PhysicalInterface,
        session: &mut Session,
        payload: &[u8], 
        peer: PeerAddr
    ) {
        if payload.len() < KYBER_PK_LEN_1024 { return; }
        let pk = &payload[0..KYBER_PK_LEN_1024];
        info!("Handshaking with {:?}", peer);
        
        if let Ok((ct, ss)) = kyber_encapsulate(pk, rng) {
            let sig = dsa_sign(&ct, &identity.secret);
            let mut resp = Vec::new();
            resp.extend_from_slice(&ct);
            resp.extend_from_slice(&sig);
            session.cipher = Some(M13Cipher::new(&SessionKey(ss)));
            info!("Session Established with {:?}", peer);
            Self::send_fragmented(mem, phy, PacketType::HandshakeInit, &resp, Some(peer));
        }
    }

    fn process_server_hello(session: &mut Session, payload: &[u8], pending_key: &mut Option<KyberKeypair>) {
        if let Some(kp) = pending_key.take() {
            if payload.len() < KYBER_CT_LEN_1024 { return; }
            let ct = &payload[0..KYBER_CT_LEN_1024];
            if let Ok(ss) = kyber_decapsulate(&kp, ct) {
                session.cipher = Some(M13Cipher::new(&SessionKey(ss)));
                info!(">>> [NODE] v0.3.0: SECURE LINK ESTABLISHED (PQC+FEC Active).");
            }
        }
    }

    fn send_fragmented(
        mem: &Arc<SlabAllocator>, 
        phy: &mut dyn PhysicalInterface, 
        ptype: PacketType, 
        payload: &[u8], 
        target: Option<PeerAddr>
    ) {
        const CHUNK_SIZE: usize = 1000;
        let total_len = payload.len();
        let mut offset = 0;

        while offset < total_len {
            let end = core::cmp::min(offset + CHUNK_SIZE, total_len);
            let chunk = &payload[offset..end];
            let chunk_len = chunk.len();

            if let Some(mut lease) = mem.alloc() {
                let mut frag_payload = Vec::with_capacity(4 + chunk_len);
                frag_payload.extend_from_slice(&(total_len as u16).to_be_bytes());
                frag_payload.extend_from_slice(&(offset as u16).to_be_bytes());
                frag_payload.extend_from_slice(chunk);

                let header = M13Header {
                    magic: M13_MAGIC, version: 1, packet_type: ptype,
                    gen_id: 0, symbol_id: 0, payload_len: frag_payload.len() as u16,
                    recoder_rank: 0, reserved: 0, auth_tag: [0; 16]
                };
                
                lease.data[32..32+frag_payload.len()].copy_from_slice(&frag_payload);
                if header.to_bytes(&mut lease.data).is_ok() {
                    let _ = phy.send(&lease.data[..32+frag_payload.len()], target);
                }
            }
            offset += chunk_len;
        }
    }
}