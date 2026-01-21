use clap::Parser;
use m13_linux::{TunDevice, LinuxPhy, LinuxHsm, LinuxClock, poll_both};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use log::info;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:443")] bind: String,
    #[arg(long, default_value = "m13hub0")] iface: String, 
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    info!(">>> M13 HUB: v0.2.0 (MULTI-TENANT) <<<");

    let mut tun = TunDevice::new(&cli.iface, "10.13.13.1", "10.13.13.2")?;
    #[cfg(target_os = "linux")]
    m13_linux::setup::configure_hub(tun.name(), "10.13.13.1/24")?;

    let socket = UdpSocket::bind(&cli.bind)?;
    socket.set_nonblocking(true)?;

    // Hub mode: No default target
    let phy = LinuxPhy::new(socket.try_clone()?, None); 
    let mem = SlabAllocator::new(4096); // Increased for multiple peers
    
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
    let mut buf = [0u8; 1500];

    loop {
        let (tun_ready, udp_ready) = poll_both(tun.fd(), socket.as_raw_fd(), 5);

        if tun_ready {
            if let Ok(n) = tun.read(&mut buf) {
                if n > 0 { 
                    let _ = kernel.send_payload(&buf[..n]);
                }
            }
        }

        if tun_ready || udp_ready { kernel.poll(); }
        else { kernel.poll(); } 

        while let Some(packet) = kernel.pop_ingress() {
            let _ = tun.write(&packet);
        }
    }
}
