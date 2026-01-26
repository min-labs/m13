use std::process::Command;
use log::info;

// Helper to run commands atomically (No Shell = No Syntax Errors)
fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program)
        .args(args)
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!("{} failed with exit code: {:?}", program, s.code())),
        Err(e) => Err(anyhow::anyhow!("Failed to execute {}: {}", program, e)),
    }
}

#[cfg(target_os = "linux")]
pub fn configure_hub(iface: &str, subnet: &str) -> anyhow::Result<()> {
    info!(">>> [AUTO] Configuring Linux Hub (NAT + Masquerade)...");

    // 1. Enable IP Forwarding
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;

    // 2. Clear old rules (Best Effort)
    let _ = Command::new("iptables").args(&["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"]).output();
    let _ = Command::new("iptables").args(&["-D", "FORWARD", "-i", iface, "-j", "ACCEPT"]).output();

    // 3. Enable NAT
    run_cmd("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"])?;

    // 4. Allow Forwarding
    run_cmd("iptables", &["-A", "FORWARD", "-i", iface, "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "FORWARD", "-o", iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])?;
    
    // 5. Set MTU
    run_cmd("ip", &["link", "set", "dev", iface, "mtu", "1280"])?;

    info!(">>> [SETUP] Linux Networking Active.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_hub(_iface: &str, _subnet: &str) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn configure_node(iface: &str, hub_endpoint: &str, _tun_gw: &str) -> anyhow::Result<()> {
    let hub_ip = hub_endpoint.split(':').next().unwrap();
    
    // [PHYSICS] RUST-NATIVE GATEWAY PARSING
    // We avoid 'sh', 'grep', and 'awk' to prevent variable expansion errors.
    let output = Command::new("route").args(&["-n", "get", "default"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse: Look for line starting with "gateway:", take the second word.
    let gateway = stdout.lines()
        .find(|line| line.trim().starts_with("gateway:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or(anyhow::anyhow!("No Gateway Detected in Route Table"))?
        .to_string();

    info!(">>> ENGAGING GLOBAL ROUTING (v0.2.1) <<<");
    info!("Detected Physical Gateway: {}", gateway);

    // 1. Pin the Hub IP to the physical gateway (bypass the VPN)
    let _ = Command::new("route").args(&["delete", hub_ip]).output(); 
    run_cmd("route", &["add", "-host", hub_ip, &gateway])?;

    // 2. Split-Tunnel Hijack (0.0.0.0/1 and 128.0.0.0/1)
    let _ = Command::new("route").args(&["delete", "0.0.0.0/1"]).output();
    let _ = Command::new("route").args(&["delete", "128.0.0.0/1"]).output();
    
    info!("Adding Global Routes to interface: {}", iface);
    run_cmd("route", &["add", "-net", "0.0.0.0/1", "-interface", iface])?;
    run_cmd("route", &["add", "-net", "128.0.0.0/1", "-interface", iface])?;
    
    info!("[SUCCESS] Routes Configured. Internet Traffic Hijacked.");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn cleanup_node(_iface: &str) {
    info!(">>> [CLEANUP] Removing Routes...");
    let _ = Command::new("route").args(&["delete", "0.0.0.0/1"]).output();
    let _ = Command::new("route").args(&["delete", "128.0.0.0/1"]).output();
}
