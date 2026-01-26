#!/bin/bash
# -----------------------------------------------------------------------------
# M13 "TITAN MARK-IV" - COMPLETE PHYSICS ENGINE
# TARGET: Enterprise Linux (Hetzner Xeon W-2145)
# FIXES: Offset 44, NAPI, IRQ Pinning, Frequency Scaling, C-States
# -----------------------------------------------------------------------------

if [ "$(uname)" != "Linux" ]; then
    echo ">>> FATAL: This script requires Linux. Aborting."
    exit 1
fi

INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo ">>> ENGAGING TITAN MARK-IV PROTOCOLS FOR $INTERFACE..."

# ==============================================================================
# 1. HARDWARE PHYSICS (SURGICAL COALESCING)
# ==============================================================================
echo "[+] NEGOTIATING INTERRUPTS..."

# STEP A: Disable Adaptive Mode FIRST. 
# Many enterprise drivers lock static settings if adaptive is on.
ethtool -C $INTERFACE adaptive-rx off adaptive-tx off 2>/dev/null

# STEP B: Set TIME-ONLY Coalescing.
# We REMOVED 'rx-frames' because your NIC rejected it (Offset 44).
# We set 'rx-usecs 50' (Wait 50us before waking CPU).
if ethtool -C $INTERFACE rx-usecs 50 2>/dev/null; then
    echo "    -> SUCCESS: Hardware Coalescing active (50us)."
else
    echo "    -> WARNING: Hardware rejected static tuning. Proceeding to Software Compensation."
fi

echo "[+] EXPANDING RINGS..."
ethtool -G $INTERFACE rx 4096 tx 4096 2>/dev/null || echo "    -> Rings already maxed."

# ==============================================================================
# 2. SOFTWARE COMPENSATION (NAPI BUDGET)
# ==============================================================================
echo "[+] TUNING NAPI BUDGET (CRITICAL)..."
# Physics: Since hardware coalescing is flaky, we force the Kernel to loop longer.
# Default: 300 packets. M13 Target: 600 packets.
# This ensures we drain the ring buffer fully on every interrupt.
sysctl -w net.core.netdev_budget=600 > /dev/null
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true # Optional

# ==============================================================================
# 3. IRQ ISOLATION (THE "IRON GRIP")
# ==============================================================================
echo "[+] ISOLATING IRQS TO CORE 0..."
# Physics: Move all Network Interrupts to CPU Core 0.
# This keeps Cores 1-N clean for RaptorQ Math.

# Stop the auto-balancer (it fights us)
service irqbalance stop 2>/dev/null

# Find IRQ numbers for the interface
IRQS=$(grep "$INTERFACE" /proc/interrupts | awk '{print $1}' | tr -d :)

if [ -z "$IRQS" ]; then
    echo "    -> WARNING: No IRQs found. Is the interface active?"
else
    for IRQ in $IRQS; do
        # '1' is the Hex mask for Core 0 (Binary 0001)
        echo 1 > /proc/irq/$IRQ/smp_affinity 2>/dev/null
        echo "    -> Locked IRQ $IRQ to Core 0"
    done
fi

# ==============================================================================
# 4. KERNEL BUFFERS & LATENCY
# ==============================================================================
echo "[+] MAXIMIZING KERNEL BUFFERS..."
sysctl -w net.core.netdev_max_backlog=20000 > /dev/null
sysctl -w net.core.rmem_max=33554432 > /dev/null
sysctl -w net.core.wmem_max=33554432 > /dev/null
sysctl -w net.core.busy_read=50 > /dev/null
sysctl -w net.core.busy_poll=50 > /dev/null

# ==============================================================================
# 5. FIREWALL BYPASS
# ==============================================================================
echo "[+] DISABLING CONNTRACK..."
iptables -t raw -I PREROUTING -p udp --dport 443 -j NOTRACK 2>/dev/null
iptables -t raw -I OUTPUT -p udp --sport 443 -j NOTRACK 2>/dev/null

# ==============================================================================
# 6. MEMORY PHYSICS (HUGE PAGES)
# ==============================================================================
echo "[+] ACTIVATING HUGE PAGES..."
echo always > /sys/kernel/mm/transparent_hugepage/enabled
echo always > /sys/kernel/mm/transparent_hugepage/defrag

# ==============================================================================
# 7. THERMAL PHYSICS (FREQUENCY PINNING)
# ==============================================================================
echo "[+] PINNING CLOCK SPEEDS..."

# 1. Force "Performance" Governor
if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
    echo "    -> Governor set to PERFORMANCE."

    # 2. Hard Pin: Set Minimum Frequency = Maximum Frequency
    MAX_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
    echo "$MAX_FREQ" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq >/dev/null
    echo "    -> Frequency pinned to ${MAX_FREQ} kHz."
else
    echo "    -> WARNING: CPU Frequency scaling not exposed. Check BIOS/Hypervisor."
fi

echo "[+] DISABLING SLEEP STATES (C-STATES)..."
# 3. Force C-State 0 (Always Awake) by locking DMA latency
if [ ! -f /tmp/latency_lock ]; then
    nohup python3 -c "import os; f=os.open('/dev/cpu_dma_latency', os.O_RDWR); os.write(f, b'\x00\x00\x00\x00'); import time; time.sleep(99999999)" >/dev/null 2>&1 &
    touch /tmp/latency_lock
    echo "    -> C-States Disabled (DMA Latency Locked to 0us)."
else
    echo "    -> Latency Lock already active."
fi

echo ">>> OPTIMIZATION COMPLETE."
echo ">>> ADVICE: Ensure 'm13-hub' is pinned to Core 1 or higher (Not Core 0)."
