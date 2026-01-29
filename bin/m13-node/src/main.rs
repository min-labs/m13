use clap::Parser;
// [PHYSICS FIX] Enable Setup on both Linux and macOS
#[cfg(any(target_os = "linux", target_os = "macos"))]
use m13_linux::setup;
use m13_linux::{TunDevice, LinuxUdp, LinuxHsm, LinuxClock};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use log::{info, warn};

// [PHYSICS] PLATFORM SPECIFIC IMPORTS (LINUX & MACOS)
// We scope these to prevent "unused import" warnings on Windows.
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[arg(long)] hub: String,
    #[arg(long, default_value = "0.0.0.0:0")] bind: String,
    #[arg(long, default_value = "utun8")] iface: String, 
    #[arg(long, default_value = "10.13.13.2")] vip: String, 
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // [COSMETIC UPDATE] v0.3.0 Identity
    info!(">>> M13 NODE: v0.3.0 (System Physics & Egress Offload) <<<");
    info!(">>> FEATURES: UDP GSO + Jemalloc + Adaptive RX + RaptorQ <<<");
    
    info!("Identity: {} on {}", cli.vip, cli.iface);

    // [PHYSICS] LINUX OPTIMIZATION ENGINE (TITAN CLIENT)
    #[cfg(target_os = "linux")]
    {
        info!(">>> [AUTO] Engaging Linux Physics Protocols...");
        
        // 1. Embed script
        const PHYSICS_SCRIPT: &str = include_str!("../optimize_linux.sh");
        let script_path = "/tmp/m13_node_physics.sh";

        // 2. Write to temp
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(script_path)?;
        file.write_all(PHYSICS_SCRIPT.as_bytes())?;

        // 3. Make executable
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms)?;

        // [CRITICAL FIX] RELEASE LOCK
        drop(file);

        // 4. Execute
        let status = Command::new(script_path).status()?;
        
        // 5. [PHYSICS CHECK] VERIFY ADAPTIVE STATE (LIAR DETECTION)
        if !status.success() {
            warn!(">>> [PHYSICS FAILURE] LIAR DETECTED!");
            warn!(">>> The NIC claimed to accept configuration but failed verification.");
            warn!(">>> Running in Non-Compliant Mode (Static Latency).");
        } else {
            info!(">>> [PHYSICS] Linux Environment Optimized & Hardware Verified.");
        }
    }

    // [PHYSICS] MACOS OPTIMIZATION ENGINE
    #[cfg(target_os = "macos")]
    {
        info!(">>> [AUTO] Engaging macOS Physics Protocols...");
        
        const PHYSICS_SCRIPT: &str = include_str!("../optimize_macos.sh");
        let script_path = "/tmp/m13_node_physics.sh";

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
            warn!(">>> [PHYSICS WARNING] Optimization script failed.");
        } else {
            info!(">>> [PHYSICS] macOS Environment Optimized.");
        }
    }

    let mut tun = TunDevice::new(&cli.iface, &cli.vip, "10.13.13.1")?;
    
    // [PHYSICS FIX] EXECUTE ROUTING CONFIGURATION ON LINUX & MACOS
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    setup::configure_node(tun.name(), &cli.hub, "10.13.13.1")?;

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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    setup::cleanup_node(tun.name());
    tun.shutdown();
    Ok(())
}
