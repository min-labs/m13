use std::process::Command;
use log::info;

#[cfg(target_os = "linux")]
pub fn configure_hub(iface: &str, subnet: &str) -> anyhow::Result<()> {
    info!(">>> [AUTO] Configuring Linux Hub (NAT + Masquerade)...");
    Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).status()?;
    let _ = Command::new("sh").arg("-c").arg("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done").status();

    let output = Command::new("sh").arg("-c").arg("ip route | grep default | awk '{print $5}' | head -n1").output()?;
    let wan = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", &wan, "-j", "MASQUERADE"]).status();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", iface, "-o", &wan, "-j", "ACCEPT"]).status();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", &wan, "-o", iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).status();
    
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "mtu", "1280"]).status();
    Ok(())
}

// [FIX] Dummy implementation for macOS to allow workspace compilation
#[cfg(not(target_os = "linux"))]
pub fn configure_hub(_iface: &str, _subnet: &str) -> anyhow::Result<()> {
    info!("Skipping Linux Hub configuration (Not on Linux)");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn configure_node(iface: &str, hub_endpoint: &str, _tun_gw: &str) -> anyhow::Result<()> {
    let hub_ip = hub_endpoint.split(':').next().unwrap();
    
    let output = Command::new("sh").arg("-c").arg("route -n get default | grep gateway | awk '{print $2}'").output()?;
    let gateway = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if gateway.is_empty() { return Err(anyhow::anyhow!("No Gateway Detected")); }

    info!(">>> ENGAGING GLOBAL ROUTING (SPRINT 27) <<<");
    let _ = Command::new("route").args(["delete", hub_ip]).output(); 
    Command::new("route").args(["add", "-host", hub_ip, &gateway]).status()?;

    let _ = Command::new("route").args(["delete", "0.0.0.0/1"]).output();
    let _ = Command::new("route").args(["delete", "128.0.0.0/1"]).output();
    
    info!("Adding Global Routes to interface: {}", iface);
    Command::new("route").args(["add", "-net", "0.0.0.0/1", "-interface", iface]).status()?;
    Command::new("route").args(["add", "-net", "128.0.0.0/1", "-interface", iface]).status()?;
    
    info!("[SUCCESS] Routes Configured. Internet Traffic Hijacked.");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn cleanup_node(_iface: &str) {
    info!(">>> [CLEANUP] Removing Routes...");
    let _ = Command::new("route").args(&["delete", "0.0.0.0/1"]).output();
    let _ = Command::new("route").args(&["delete", "128.0.0.0/1"]).output();
}
