use clap::Parser;
use m13_linux::{TunDevice, LinuxUdp, LinuxHsm, LinuxClock};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use log::info;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:443")] bind: String,
    #[arg(long, default_value = "m13hub0")] iface: String, 
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // [COSMETIC UPDATE] v0.2.0 Identity
    info!(">>> M13 HUB: v0.2.0 (HIGH-PERF DATA PLANE) <<<");
    info!(">>> FEATURES: Vector I/O + BBRv3 + RaptorQ FEC <<<");

    let mut tun = TunDevice::new(&cli.iface, "10.13.13.1", "10.13.13.2")?;
    #[cfg(target_os = "linux")]
    m13_linux::setup::configure_hub(tun.name(), "10.13.13.1/24")?;

    // [FIX] Hub now uses Liquid Vector Driver (Socket2 + 4MB Buffers)
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
