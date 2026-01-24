use clap::Parser;
#[cfg(target_os = "macos")]
use m13_linux::setup;
use m13_linux::{TunDevice, LinuxUdp, LinuxHsm, LinuxClock};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use log::{info, warn};

#[derive(Parser)]
struct Cli {
    #[arg(long)] hub: String,
    #[arg(long, default_value = "0.0.0.0:0")] bind: String,
    #[arg(long, default_value = "utun8")] iface: String, 
    #[arg(long, default_value = "10.13.13.2")] vip: String, 
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // [COSMETIC UPDATE] v0.2.0 Identity
    info!(">>> M13 NODE: v0.2.0 (HIGH-PERF DATA PLANE) <<<");
    info!(">>> FEATURES: Vector I/O + BBRv3 + RaptorQ FEC <<<");
    
    info!("Identity: {} on {}", cli.vip, cli.iface);

    let mut tun = TunDevice::new(&cli.iface, &cli.vip, "10.13.13.1")?;
    
    #[cfg(target_os = "macos")]
    setup::configure_node(tun.name(), &cli.hub, "10.13.13.1")?;

    // LIQUID VECTOR DRIVER
    let phy = LinuxUdp::new(&cli.bind, Some(&cli.hub))?;
    let mem = SlabAllocator::new(4096);
    
    let mut rng = rand::thread_rng();
    let identity = DsaKeypair::generate(&mut rng)?; 

    let config = KernelConfig {
        is_hub: false,
        enable_encryption: true,
    };

    let mut kernel = M13Kernel::new(
        Box::new(phy), Box::new(LinuxHsm), Box::new(LinuxClock::new()), 
        mem, config, identity
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        warn!("Signal received. Stopping...");
        r.store(false, Ordering::SeqCst);
    })?;

    info!("Node Kernel Active. Initiating Handshake...");
    let mut buf = [0u8; 65535];
    let mut tunnel_confirmed = false;

    while running.load(Ordering::SeqCst) {
        let mut work_done = false;

        // 1. UPLINK BATCH
        for _ in 0..64 {
            match tun.read(&mut buf) {
                Ok(n) if n > 0 => {
                    kernel.send_payload(&buf[..n]).ok();
                    work_done = true;
                },
                _ => break,
            }
        }

        // 2. KERNEL BATCH
        if kernel.poll() { work_done = true; }

        // 3. DOWNLINK BATCH
        while let Some(packet) = kernel.pop_ingress() {
            if !tunnel_confirmed {
                info!(">>> [NODE] TUNNEL ACTIVE (Round Trip Confirmed).");
                tunnel_confirmed = true;
            }
            let _ = tun.write(&packet);
            work_done = true;
        }

        // 4. ADAPTIVE YIELD
        if !work_done {
             std::thread::yield_now(); 
        }
    }

    #[cfg(target_os = "macos")]
    setup::cleanup_node(tun.name());
    tun.shutdown();
    Ok(())
}
