use clap::Parser;
use m13_linux::{TunDevice, LinuxUdp, LinuxHsm, LinuxClock};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use log::{info, warn};

// [PHYSICS] PLATFORM SPECIFIC IMPORTS (LINUX ONLY)
#[cfg(target_os = "linux")]
use std::{
    process::Command,
    io::Write,
    fs::OpenOptions,
    os::unix::fs::PermissionsExt,
};

// [PHYSICS] MEMORY ALLOCATOR
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:443")] bind: String,
    #[arg(long, default_value = "m13hub0")] iface: String, 
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // [COSMETIC UPDATE] v0.3.0 Identity
    info!(">>> M13 HUB: v0.3.0 (System Physics & Egress Offload) <<<");
    info!(">>> FEATURES: UDP GSO + Jemalloc + Adaptive RX + RaptorQ <<<");

    // [PHYSICS] AUTOMATED OPTIMIZATION ENGINE
    #[cfg(target_os = "linux")]
    {
        info!(">>> [AUTO] Engaging Physics Optimization Protocols...");
        
        const PHYSICS_SCRIPT: &str = include_str!("../optimize_linux.sh");
        let script_path = "/tmp/m13_physics_engine.sh";

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(script_path)?;
        
        file.write_all(PHYSICS_SCRIPT.as_bytes())?;
        
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms)?;
        
        drop(file);
        
        let status = Command::new(script_path).status()?;
        
        if !status.success() {
            warn!(">>> [PHYSICS FAILURE] LIAR DETECTED!");
            warn!(">>> The NIC claimed to accept configuration but failed verification.");
            warn!(">>> Running in Non-Compliant Mode (Static Latency).");
        } else {
            info!(">>> [PHYSICS] Environment Optimized & Hardware Compliance Verified.");
        }
    }

    // [PHYSICS] CPU PINNING
    if let Some(core_ids) = core_affinity::get_core_ids() {
        if let Some(target_core) = core_ids.last() {
            let is_safe = target_core.id != 0;
            let is_single_core = core_ids.len() == 1;

            if is_safe || is_single_core {
                if core_affinity::set_for_current(*target_core) {
                    if is_safe {
                        info!(">>> PHYSICS: Process Pinned to Core ID {} (SAFE ZONE).", target_core.id);
                    } else {
                        warn!(">>> PHYSICS WARNING: Running on Core 0 (IRQ Warzone). No other cores available.");
                    }
                }
            }
        }
    } else {
        warn!(">>> PHYSICS FAILURE: Could not detect CPU Topology. Running unpinned.");
    }

    let mut tun = TunDevice::new(&cli.iface, "10.13.13.1", "10.13.13.2")?;
    #[cfg(target_os = "linux")]
    m13_linux::setup::configure_hub(tun.name(), "10.13.13.1/24")?;

    let phy = LinuxUdp::new(&cli.bind, None)?;
    let mem = SlabAllocator::new(8192); 
    let mut rng = rand::thread_rng();
    let identity = DsaKeypair::generate(&mut rng)?; 

    let config = KernelConfig {
        is_hub: true,
        enable_encryption: true,
    };

    let mut kernel = M13Kernel::new(
        Box::new(phy), Box::new(LinuxHsm), Box::new(LinuxClock::new()), 
        mem, config, identity
    );

    info!("Hub Active. Waiting for peers on {}...", cli.bind);
    let mut buf = [0u8; 65535];

    loop {
        let mut work_done = false;

        // 1. INGRESS BATCH
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

        // 3. EGRESS BATCH
        while let Some(packet) = kernel.pop_ingress() {
            let _ = tun.write(&packet);
            work_done = true;
        }

        // 4. ADAPTIVE YIELD
        if !work_done {
            std::thread::yield_now();
        }
    }
}
