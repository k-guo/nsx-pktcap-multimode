#!/usr/bin/env bash
# =============================================================================
# nsx-pktcap-multimode — NSX / ESXi Multi-Mode Packet Capture
# -----------------------------------------------------------------------------
# Captures simultaneously at multiple points in the ESXi network stack via
# pktcap-uw over SSH (direct/uplink/vmk modes) or via the NSX Policy API.
#
# Four capture modes:
#
#   api    (default) — NSX Policy API capture at SEGMENTPORT.
#                      Good for standard IP/TCP/UDP traffic.
#                      Supports --src / --dst IP filters.
#                      Requires VM to have a vNIC on an NSX segment.
#                      Does NOT see ENS fast-path or L2-only traffic.
#
#   direct           — SSH to the ESXi host and capture on the VM's switchport.
#                      Captures at VnicRx, VnicTx, ENSInput and Drop
#                      simultaneously. Works for ANY VM on the host, whether
#                      or not its vNIC is connected to an NSX segment.
#                      Required for:
#                        • PROFINET (EtherType 0x8892)
#                        • PTP      (EtherType 0x88f7)
#                        • Any L2-only multicast over ENS
#                      Use --host <IP> to bypass the NSX VM lookup (required
#                      if the VM's host is not an NSX transport node).
#
#   uplink           — SSH to the ESXi host and capture on a physical vmnic.
#                      Captures UplinkRcv and UplinkSnd simultaneously.
#                      Captures at the VMkernel/NIC boundary by default
#                      (UplinkRcvKernel,UplinkSndKernel) — reliable for ENS
#                      environments and L2 protocols like PROFINET.
#                      --host <IP> and --uplink <vmnic> are both required.
    #                      Use this to confirm:
    #                        • Traffic arrives at the physical NIC
    #                        • Traffic is leaving the host
    #                        • Unicast frames destined for a VM MAC arrive
#
#   vmk              — SSH to the ESXi host and capture on a VMkernel NIC.
#                      Captures management, vMotion, vSAN, or NFS traffic
#                      flowing through a vmk interface.
#                      --host <IP> and --vmk <vmkN> are both required.
#
# ---- Capture point stack (top = closest to wire) ----
#
#   Physical wire
#     ↕  NIC driver
#   [--uplink vmnicX --dir 2]          raw NIC driver level (wire-tap)
#     ↕  VMkernel boundary
#   [UplinkRcvKernel / UplinkSndKernel]  VMkernel/NIC boundary  ← default for uplink mode
#     ↕  DVS portset
#   [UplinkRcv / UplinkSnd]             DVS portset level
#     ↕  DVS logical port
#   [PortInput / PortOutput]           = SEGMENTPORT in NSX API
#     ↕  vNIC driver
#   [VnicRx / VnicTx]                  VM vNIC driver  ← default for direct mode
#   [ENSInput]                         ENS fast-path (sender side)
#   [Drop]                             dropped at vSwitch
#     ↕
#   VM guest OS
#
# NOTE on UplinkRcvKernel vs UplinkRcv:
#   UplinkRcvKernel/SndKernel — VMkernel/NIC boundary (script DEFAULT for uplink mode).
#                               Most reliable for ENS, PROFINET, and PTP.
#   UplinkRcv/UplinkSnd       — DVS portset boundary (one layer above Kernel).
#                               May miss ENS fast-path traffic.
#
# Usage:
#   api:    ./nsx-pktcap-multimode.sh [OPTIONS] <VM_NAME> <MAC_ADDRESS>
#   direct: ./nsx-pktcap-multimode.sh --mode direct [--host <IP>] [OPTIONS] <VM_NAME> <MAC_ADDRESS>
#   uplink: ./nsx-pktcap-multimode.sh --mode uplink --host <IP> --uplink <vmnic> [OPTIONS]
#   vmk:    ./nsx-pktcap-multimode.sh --mode vmk    --host <IP> --vmk <vmkN>     [OPTIONS]
#
# Options:
#   --mode api|direct|uplink|vmk  Capture mode (default: api)
#   --host <IP>       ESXi host management IP
#                     direct: optional — skips NSX VM lookup (required if host
#                             is not an NSX transport node)
#                     uplink/vmk: required
#   --uplink <vmnic>  Physical NIC to capture on (required: uplink mode)
#   --vmk <vmkN>      VMkernel NIC to capture on, e.g. vmk0 (required: vmk mode)
#   --ethtype <hex>   EtherType filter, e.g. 0x8892 (direct/uplink/vmk modes)
#   --proto <hex>     IP protocol filter, e.g. 0x1=ICMP 0x6=TCP 0x11=UDP
#                     (direct/uplink/vmk modes)
#   --src <IP>        Source IP filter (api mode only)
#   --dst <IP>        Destination IP filter (api mode only)
#   --srcmac <MAC>    Source MAC filter (direct/uplink/vmk modes)
#   --dstmac <MAC>    Destination MAC filter (direct/uplink/vmk modes)
#   --vlan <N>        VLAN ID filter (uplink/vmk modes)
#   --ip <IP>         IP address filter — matches src OR dst (direct/uplink/vmk modes)
#   --rcf <expr>      Raw capture filter, e.g. 'geneve and host 10.0.0.1'
#                     (direct/uplink/vmk modes) — quote the expression
#   --duration <sec>  Capture window in seconds (default: 60)
#   --amount <n>      Max packets per capture point before auto-stop (default: 1000)
#   --snaplen <n>     Bytes per packet captured (default: 1500; 0 = full packet)
#   --points <list>   Comma-separated pktcap-uw capture points
#                     Default for direct: VnicRx,VnicTx,ENSInput,Drop
#                     Default for uplink: UplinkRcvKernel,UplinkSndKernel
#   --out <dir>       Local directory to save .pcapng files (default: .)
#
# Examples:
#   # NSX API: all traffic for a VM (no SSH needed)
#   ./nsx-pktcap-multimode.sh my-vm 00:50:56:b2:50:c8
#
#   # NSX API: filter by source and destination IP
#   ./nsx-pktcap-multimode.sh --src 10.1.1.5 --dst 10.1.1.10 my-vm 00:50:56:b2:50:c8
#
#   # Direct: capture all traffic on VM vNIC at 4 points (VnicRx,VnicTx,ENSInput,Drop)
#   ./nsx-pktcap-multimode.sh --mode direct my-vm 00:50:56:b2:50:c8
#
#   # Direct: TCP only on VM vNIC
#   ./nsx-pktcap-multimode.sh --mode direct --proto 0x6 my-vm 00:50:56:b2:50:c8
#
#   # Direct: PROFINET traffic (EtherType 0x8892) on VM vNIC
#   ./nsx-pktcap-multimode.sh --mode direct --ethtype 0x8892 ievd-vlan-107 00:50:56:a7:1a:5d
#
#   # Direct: bypass NSX host lookup (VM not on NSX segment, or host not a transport node)
#   ./nsx-pktcap-multimode.sh --mode direct --host 10.1.1.203 my-vm 00:50:56:a7:bb:80
#
#   # Uplink: all traffic on VLAN 107 (both directions)
#   ./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 --vlan 107
#
#   # Uplink: UDP traffic to/from a specific host
#   ./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
#       --proto 0x11 --ip 10.1.1.55 --vlan 107
#
#   # Uplink: unicast to a specific VM's MAC
#   ./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
#       --dstmac 00:50:56:a7:31:43 --vlan 107
#
#   # Uplink: PROFINET traffic (EtherType 0x8892)
#   ./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
#       --ethtype 0x8892 --vlan 107
#
#   # VMk: all traffic on vmk0 (management / vMotion / vSAN / NFS)
#   ./nsx-pktcap-multimode.sh --mode vmk --host 10.1.1.203 --vmk vmk0
#
#   # VMk: ICMP only (proto 0x1)
#   ./nsx-pktcap-multimode.sh --mode vmk --host 10.1.1.203 --vmk vmk0 --proto 0x1
#
# Requirements: curl, python3, ssh, scp (direct/uplink/vmk modes need sshpass or key auth)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# CONFIGURATION — update these before running
# -----------------------------------------------------------------------------
NSX_MGR="https://your-nsx-manager"    # e.g. https://10.0.0.1 or https://nsx.example.com
NSX_USER="admin"
NSX_PASS="your-nsx-password"
# Note: vCenter credentials are not required — all VM, vNIC, and port inventory
# is queried directly from the NSX Manager, which syncs it from vCenter.

ESXI_USER="root"
ESXI_PASS="your-esxi-password"        # used in direct, uplink, and vmk modes (sshpass)

# Capture settings
CAP_DIRECTION="DUAL"       # INPUT | OUTPUT | DUAL  (NOTE: "DUAL" = both directions — the NSX API
                           # does not accept "BOTH"; DUAL is the correct value for bidirectional)
CAP_DURATION=60            # seconds
CAP_AMOUNT=1000            # max packets per capture point
CAP_SNAPLEN=1500           # bytes per packet (0 = full packet)
OUTPUT_DIR="."             # local directory to save .pcap files
# -----------------------------------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# Prompt for confirmation unless --yes was passed or stdin is not a terminal.
# Usage: confirm "Warning message"
confirm() {
    warn "$1"
    if [[ "${FORCE:-false}" == "true" ]]; then
        warn "  (skipping confirmation — --yes was passed)"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        die "Running non-interactively. Pass --yes to skip confirmations, or add filters to narrow the capture."
    fi
    printf "${YELLOW}  Proceed? [y/N]${NC} "
    read -r _REPLY </dev/tty
    [[ "$_REPLY" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
}

# Check VMFS free space after remote dir is created.
# Aborts if < 500 MB free on the datastore.
check_vmfs_space() {
    local remote_dir="$1"
    local free_kb free_mb
    free_kb=$(esxi_ssh "df -k '${remote_dir}' 2>/dev/null | awk 'NR==2{print \$4}'" | tr -d ' \n') || true
    free_mb=$(( ${free_kb:-0} / 1024 ))
    if [[ "${free_kb:-0}" -lt 524288 ]]; then   # < 512 MB
        die "VMFS datastore has only ${free_mb} MB free — aborting to protect the datastore.\n  Reduce --amount / --snaplen, or free space on the datastore first."
    fi
    info "  VMFS free space : ${free_mb} MB  (on $(dirname "$remote_dir"))"
}

# Test SSH connectivity to the ESXi host; die early with a clear message if unreachable.
check_ssh_connectivity() {
    local result
    result=$(esxi_ssh "echo ok" 2>&1) || true
    if [[ "${result}" != "ok" ]]; then
        die "Cannot connect to ESXi host ${ESXI_HOST_IP} via SSH.\n  - Verify the host is reachable: ping ${ESXI_HOST_IP}\n  - Verify SSH is enabled: Services > SSH in the ESXi host UI\n  - Verify credentials (ESXI_USER / ESXI_PASS at top of script)"
    fi
    success "SSH connection to ${ESXI_HOST_IP}: OK"
}

# Warn if pktcap-uw is already running on the host (limited capture session pool).
check_pktcap_running() {
    local running
    running=$(esxi_ssh "pgrep pktcap-uw 2>/dev/null | wc -l" | tr -d ' \n') || true
    if [[ "${running:-0}" -gt 0 ]]; then
        confirm "pktcap-uw is already running on ${ESXI_HOST_IP} (${running} process(es)).\n  ESXi has a limited capture session pool. Multiple simultaneous captures may impact host performance."
    fi
}

# Verify the specified uplink NIC exists on the host.
# If SSH is unreachable, warns and skips (the capture will fail with a clearer error).
# If SSH works but NIC is absent, dies and shows the available NIC list.
check_uplink_exists() {
    local nic="$1" output
    output=$(esxi_ssh "esxcli network nic list 2>/dev/null" 2>/dev/null) || true
    if [[ -z "$output" ]]; then
        warn "Could not retrieve NIC list from ${ESXI_HOST_IP} — skipping pre-flight check."
        return 0
    fi
    if ! echo "$output" | grep -q "^${nic}[[:space:]]"; then
        die "Uplink '${nic}' not found on ${ESXI_HOST_IP}.\n  Available NICs:\n$(echo "$output" | grep -v '^-' | tail -n +2 | awk '{print "    "$1}')\n  Run on ESXi:  esxcli network nic list"
    fi
    success "Uplink '${nic}' confirmed."
}

# Verify the specified VMkernel NIC exists on the host.
# esxcli network ip interface list outputs each vmk name as a bare standalone line
# (no trailing space), with properties indented below. Match with ^vmk$ exactly.
check_vmk_exists() {
    local vmk="$1" output vmk_list
    output=$(esxi_ssh "esxcli network ip interface list 2>/dev/null" 2>/dev/null) || true
    if [[ -z "$output" ]]; then
        warn "Could not retrieve interface list from ${ESXI_HOST_IP} — skipping pre-flight check."
        return 0
    fi
    if ! echo "$output" | grep -q "^${vmk}$"; then
        vmk_list=$(echo "$output" | grep -E '^[a-zA-Z][a-zA-Z0-9_-]*$' | awk '{print "    "$1}')
        die "VMkernel interface '${vmk}' not found on ${ESXI_HOST_IP}.\n  Available interfaces:\n${vmk_list}\n  Run on ESXi:  esxcli network ip interface list"
    fi
    success "Interface '${vmk}' confirmed."
}

print_usage() {
    echo -e "${BOLD}USAGE${NC}"
    echo "  api / direct:"
    echo "    $(basename "$0") [OPTIONS] <VM_NAME> <MAC_ADDRESS>"
    echo ""
    echo "  uplink  (physical NIC — requires --host and --uplink):"
    echo "    $(basename "$0") --mode uplink --host <ESXi_IP> --uplink <vmnic> [OPTIONS]"
    echo ""
    echo "  vmk  (VMkernel NIC — requires --host and --vmk):"
    echo "    $(basename "$0") --mode vmk --host <ESXi_IP> --vmk <vmkN> [OPTIONS]"
    echo ""
    echo -e "${BOLD}MODES${NC}"
    echo "  api      NSX Policy API capture at SEGMENTPORT (default)."
    echo "           Requires VM to be on an NSX segment. No SSH needed."
    echo "           Does NOT see ENS fast-path or L2-only traffic."
    echo ""
    echo "  direct   SSH to ESXi and capture on the VM's switchport."
    echo "           Works for any VM — NSX segment not required."
    echo "           Captures VnicRx, VnicTx, ENSInput, Drop in parallel."
    echo "           Add --host <IP> to skip the NSX VM lookup entirely."
    echo ""
    echo "  uplink   SSH to ESXi and capture on a physical vmnic."
    echo "           Captures at the VMkernel/NIC boundary (best for ENS/PROFINET)."
    echo "           Confirms traffic at the physical wire level."
    echo ""
    echo "  vmk      SSH to ESXi and capture on a VMkernel NIC (vmk0, vmk1, ...)."
    echo "           Management, vMotion, vSAN, NFS, and iSCSI traffic."
    echo ""
    echo -e "${BOLD}OPTIONS${NC}"
    echo "  --mode api|direct|uplink|vmk   Capture mode (default: api)"
    echo "  --host   <IP>     ESXi host IP. Required for uplink/vmk."
    echo "                    Optional for direct (bypasses NSX VM lookup)."
    echo "  --uplink <vmnic>  Physical NIC (required: uplink). Find: esxcli network vswitch dvs vmware list"
    echo "  --vmk    <vmkN>   VMkernel NIC (required: vmk).   Find: esxcli network ip interface list"
    echo "  --ethtype <hex>   EtherType filter  e.g. 0x8892=PROFINET 0x88f7=PTP 0x88fb=PRP (direct/uplink/vmk)"
    echo "  --proto   <hex>   IP protocol filter e.g. 0x1=ICMP 0x6=TCP 0x11=UDP (direct/uplink/vmk)"
    echo "  --ip     <IP>     IP address filter — matches src OR dst (direct/uplink/vmk)"
    echo "  --rcf    <expr>   Raw capture filter e.g. 'geneve and host 10.0.0.1' (direct/uplink/vmk)"
    echo "                    Used for NSX/Geneve overlay traffic. Quote the expression."
    echo "  --src    <IP>     Source IP filter (api mode only)"
    echo "  --dst    <IP>     Destination IP filter (api mode only)"
    echo "  --srcmac <MAC>    Source MAC filter (direct/uplink/vmk)"
    echo "  --dstmac <MAC>    Destination MAC filter (direct/uplink/vmk)"
    echo "  --vlan   <N>      VLAN ID filter (uplink/vmk)"
    echo "  --duration <sec>  Capture duration in seconds (default: 60)"
    echo "  --amount <n>      Max packets per capture point (default: 1000)"
    echo "  --snaplen <n>     Bytes per packet (default: 1500; 0 = full packet)"
    echo "  --points <list>   Comma-separated pktcap-uw capture points"
    echo "                    direct default: VnicRx,VnicTx,ENSInput,Drop"
    echo "                    uplink default: UplinkRcvKernel,UplinkSndKernel"
    echo "  --out    <dir>    Output directory for .pcapng files (default: .)"
    echo "  --yes|-y          Skip all interactive confirmation prompts (for scripted use)"
    echo "  --help            Show this help message"
    echo ""
    echo -e "${BOLD}EXAMPLES${NC}"
    echo "  # NSX API: all traffic for a VM (no SSH)"
    echo "  $(basename "$0") my-vm 00:50:56:b2:50:c8"
    echo ""
    echo "  # NSX API: filter by source and destination IP"
    echo "  $(basename "$0") --src 10.1.1.5 --dst 10.1.1.10 my-vm 00:50:56:b2:50:c8"
    echo ""
    echo "  # Direct: capture all traffic at 4 points (VnicRx,VnicTx,ENSInput,Drop)"
    echo "  $(basename "$0") --mode direct my-vm 00:50:56:b2:50:c8"
    echo ""
    echo "  # Direct: TCP only on VM vNIC"
    echo "  $(basename "$0") --mode direct --proto 0x6 my-vm 00:50:56:b2:50:c8"
    echo ""
    echo "  # Direct: PROFINET traffic (EtherType 0x8892) on VM vNIC"
    echo "  $(basename "$0") --mode direct --ethtype 0x8892 ievd-vlan-107 00:50:56:a7:1a:5d"
    echo ""
    echo "  # Direct: bypass NSX lookup (VM not on NSX segment or host not a transport node)"
    echo "  $(basename "$0") --mode direct --host 10.1.1.203 my-vm 00:50:56:a7:bb:80"
    echo ""
    echo "  # Uplink: all traffic on VLAN 107 (UplinkRcvKernel + UplinkSndKernel)"
    echo "  $(basename "$0") --mode uplink --host 10.1.1.201 --uplink vmnic2 --vlan 107"
    echo ""
    echo "  # Uplink: UDP traffic to/from a specific host"
    echo "  $(basename "$0") --mode uplink --host 10.1.1.201 --uplink vmnic2 --proto 0x11 --ip 10.1.1.55 --vlan 107"
    echo ""
    echo "  # Uplink: unicast to a VM's MAC"
    echo "  $(basename "$0") --mode uplink --host 10.1.1.201 --uplink vmnic2 --dstmac 00:50:56:a7:31:43 --vlan 107"
    echo ""
    echo "  # Uplink: PROFINET traffic (EtherType 0x8892)"
    echo "  $(basename "$0") --mode uplink --host 10.1.1.201 --uplink vmnic2 --ethtype 0x8892 --vlan 107"
    echo ""
    echo "  # VMk: ICMP on vmk0"
    echo "  $(basename "$0") --mode vmk --host 10.1.1.201 --vmk vmk0 --proto 0x1"
    echo ""
}

# nsx_curl <METHOD> <path> [extra curl args...]
nsx_curl() {
    local method="$1"; shift
    local path="$1";   shift
    local http_code tmp body
    tmp=$(mktemp)
    http_code=$(curl -sk \
        -u "${NSX_USER}:${NSX_PASS}" \
        -X "$method" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -w "%{http_code}" \
        -o "$tmp" \
        "$@" \
        "${NSX_MGR}${path}")
    body=$(cat "$tmp"); rm -f "$tmp"
    if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
        die "NSX API [HTTP $http_code]: $method ${NSX_MGR}${path}\n$body"
    fi
    echo "$body"
}

json_get() {
    python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print($1)" <<< "$2"
}

esxi_ssh() {
    sshpass -p "${ESXI_PASS}" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o LogLevel=ERROR \
        "${ESXI_USER}@${ESXI_HOST_IP}" "$@"
}

esxi_scp() {
    # On macOS, the first sshpass/scp call in a session can fail due to DISPLAY/askpass
    # race conditions. One retry after a brief pause reliably resolves it.
    sshpass -p "${ESXI_PASS}" scp \
        -o StrictHostKeyChecking=no \
        -o LogLevel=ERROR \
        "${ESXI_USER}@${ESXI_HOST_IP}:$1" "$2" 2>/dev/null && return 0
    sleep 1
    sshpass -p "${ESXI_PASS}" scp \
        -o StrictHostKeyChecking=no \
        -o LogLevel=ERROR \
        "${ESXI_USER}@${ESXI_HOST_IP}:$1" "$2"
}

# resolve_host_ip <HOST_ID>
# Resolves NSX fabric host_id → ESXi management IP.
resolve_host_ip() {
    local host_id="$1"
    local ip="" resp

    resp=$(nsx_curl GET "/api/v1/transport-nodes/${host_id}" 2>/dev/null || true)
    if [[ -n "$resp" ]]; then
        ip=$(python3 -c "
import json
d = json.loads('''${resp}''')
try:
    mgmt = d['node_deployment_info']['ip_addresses']
    print(mgmt[0] if isinstance(mgmt, list) else mgmt)
except:
    pass
" 2>/dev/null || true)
    fi

    if [[ -z "$ip" ]]; then
        resp=$(nsx_curl GET "/api/v1/fabric/nodes/${host_id}" 2>/dev/null || true)
        ip=$(python3 -c "
import json
d = json.loads('''${resp}''')
ips = d.get('ip_addresses', [])
print(ips[0] if ips else '')
" 2>/dev/null || true)
    fi

    echo "$ip"
}

# find_vmfs_dir <label>
# Picks the first non-vSAN VMFS datastore on the ESXi host and creates a capture dir.
# Avoids /tmp — filling ESXi's RAM-backed /tmp can crash hostd (KB 341568).
find_vmfs_dir() {
    local label="$1"
    esxi_ssh "
        ds=\$(df -h 2>/dev/null | grep '/vmfs/volumes/' | grep -v 'vsanDatastore\|vSAN' | head -1 | awk '{print \$NF}')
        if [[ -z \"\$ds\" ]]; then
            ds=\$(df -h 2>/dev/null | grep '/vmfs/volumes/' | head -1 | awk '{print \$NF}')
        fi
        capdir=\"\${ds}/pktcap_${label}\"
        mkdir -p \"\$capdir\" 2>/dev/null
        echo \"\$capdir\"
    "
}

# launch_captures <remote_dir> <filter_args> <points_csv> <file_prefix> <port_arg>
# Starts one pktcap-uw process per capture point in the background on the ESXi host.
# Sets globals: REMOTE_PCAPS (array), POINT_LABELS (array)
REMOTE_PCAPS=()
POINT_LABELS=()

launch_captures() {
    local remote_dir="$1"
    local filter_args="$2"
    local points_csv="$3"
    local file_prefix="$4"
    local port_arg="$5"     # "--switchport <ID>" or "--uplink <vmnic>"

    REMOTE_PCAPS=()
    POINT_LABELS=()

    IFS=',' read -ra POINTS_ARR <<< "$points_csv"
    for POINT in "${POINTS_ARR[@]}"; do
        POINT=$(echo "$POINT" | tr -d ' ')
        REMOTE_PCAP="${remote_dir}/${file_prefix}_${POINT}.pcapng"
        REMOTE_PCAPS+=("$REMOTE_PCAP")
        POINT_LABELS+=("$POINT")

        # NOTE: -G is a tcpdump flag and is NOT valid for pktcap-uw.
        # Duration is controlled externally: the script sleeps for CAP_DURATION
        # then kills all pktcap-uw processes. Only -c (packet count) is used here.
        # -s sets the snaplen (bytes per packet; 0 = full packet).
        CMD="pktcap-uw --capture ${POINT} ${port_arg} ${filter_args} -e -s ${CAP_SNAPLEN} -o \"${REMOTE_PCAP}\" -c ${CAP_AMOUNT} >/dev/null 2>&1 &"
        esxi_ssh "eval '$CMD'" || true
        success "  Started ${POINT} → ${REMOTE_PCAP}"
    done
}

# wait_and_collect <file_prefix>
# Waits for captures, kills processes, downloads files. Sets global: DOWNLOADED (array).
DOWNLOADED=()

wait_and_collect() {
    local file_prefix="$1"

    echo ""
    warn "All captures running for ${CAP_DURATION}s. Generate traffic now if needed..."

    for (( t=0; t<CAP_DURATION; t+=10 )); do
        sleep 10
        remaining=$(( CAP_DURATION - t - 10 ))
        [[ $remaining -gt 0 ]] && printf "  %3ds remaining...\n" "$remaining"
    done

    info "Stopping captures..."
    esxi_ssh "kill \$(lsof 2>/dev/null | grep pktcap-uw | awk '{print \$1}' | sort -u) 2>/dev/null || true" || true
    sleep 2
    success "Captures stopped."

    echo ""
    info "Downloading .pcap files..."
    DOWNLOADED=()
    for i in "${!REMOTE_PCAPS[@]}"; do
        REMOTE_PCAP="${REMOTE_PCAPS[$i]}"
        POINT_LABEL="${POINT_LABELS[$i]}"
        LOCAL_PCAP="${OUTPUT_DIR}/${file_prefix}_${POINT_LABEL}_${TIMESTAMP}.pcapng"

        FILE_SIZE=$(esxi_ssh "wc -c < \"${REMOTE_PCAP}\" 2>/dev/null || echo 0" | tr -d ' \n') || true
        if [[ "${FILE_SIZE:-0}" -gt 24 ]]; then
            esxi_scp "$REMOTE_PCAP" "$LOCAL_PCAP"
            ACTUAL_SIZE=$(wc -c < "$LOCAL_PCAP" | tr -d ' ')
            success "  ${POINT_LABEL}: ${LOCAL_PCAP} (${ACTUAL_SIZE} bytes)"
            DOWNLOADED+=("${POINT_LABEL}:${LOCAL_PCAP}")
        else
            warn "  ${POINT_LABEL}: empty or missing — no packets at this point."
        fi
    done
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
[[ $# -eq 0 ]] && { print_usage; exit 1; }

CAP_MODE="api"
HOST_ARG=""
UPLINK_NIC=""
VMK_NIC=""
ETHTYPE=""
PROTO=""
IP_FILTER=""
RCF_FILTER=""
SRC_IP=""
DST_IP=""
SRC_MAC=""
DST_MAC=""
VLAN_ID=""
CAP_POINTS=""   # empty = use mode default
FORCE=false     # --yes skips interactive confirmations

# Flags and positional args may appear in any order.
# Non-flag words are collected into POSITIONALS and assigned after the loop.
POSITIONALS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)  print_usage; exit 0 ;;
        --mode)     CAP_MODE="$2";     shift 2 ;;
        --host)     HOST_ARG="$2";     shift 2 ;;
        --uplink)   UPLINK_NIC="$2";   shift 2 ;;
        --vmk)      VMK_NIC="$2";      shift 2 ;;
        --ethtype)  ETHTYPE="$2";      shift 2 ;;
        --proto)    PROTO="$2";        shift 2 ;;
        --ip)       IP_FILTER="$2";    shift 2 ;;
        --rcf)      RCF_FILTER="$2";   shift 2 ;;
        --src)      SRC_IP="$2";       shift 2 ;;
        --dst)      DST_IP="$2";       shift 2 ;;
        --srcmac)   SRC_MAC="$2";      shift 2 ;;
        --dstmac)   DST_MAC="$2";      shift 2 ;;
        --vlan)     VLAN_ID="$2";      shift 2 ;;
        --duration) CAP_DURATION="$2"; shift 2 ;;
        --amount)   CAP_AMOUNT="$2";   shift 2 ;;
        --snaplen)  CAP_SNAPLEN="$2";  shift 2 ;;
        --points)   CAP_POINTS="$2";   shift 2 ;;
        --out)      OUTPUT_DIR="$2";   shift 2 ;;
        --yes|-y)   FORCE=true;    shift ;;
        --*)        die "Unknown option: $1\nRun '$(basename "$0") --help' for usage." ;;
        *)          POSITIONALS+=("$1"); shift ;;
    esac
done

# Validate mode
[[ "$CAP_MODE" != "api" && "$CAP_MODE" != "direct" && \
   "$CAP_MODE" != "uplink" && "$CAP_MODE" != "vmk" ]] && \
    die "--mode must be one of: api, direct, uplink, vmk"

# Positional args
case "$CAP_MODE" in
    api|direct)
        if [[ ${#POSITIONALS[@]} -lt 2 ]]; then
            echo -e "${RED}[ERROR]${NC} VM_NAME and MAC_ADDRESS are required for ${CAP_MODE} mode." >&2
            echo "" >&2
            print_usage >&2
            exit 1
        fi
        VM_NAME="${POSITIONALS[0]}"
        MAC_ADDRESS=$(echo "${POSITIONALS[1]}" | tr '[:upper:]' '[:lower:]')
        ;;
    uplink)
        [[ -z "$HOST_ARG"   ]] && die "--host <ESXi_IP> is required for uplink mode.\nRun '$(basename "$0") --help' for usage."
        [[ -z "$UPLINK_NIC" ]] && die "--uplink <vmnic> is required for uplink mode.\n  Find it with:  esxcli network vswitch dvs vmware list\nRun '$(basename "$0") --help' for usage."
        VM_NAME=""; MAC_ADDRESS=""
        ;;
    vmk)
        [[ -z "$HOST_ARG" ]] && die "--host <ESXi_IP> is required for vmk mode.\nRun '$(basename "$0") --help' for usage."
        [[ -z "$VMK_NIC"  ]] && die "--vmk <vmkN> is required for vmk mode.\n  Find interfaces with:  esxcli network ip interface list\nRun '$(basename "$0") --help' for usage."
        VM_NAME=""; MAC_ADDRESS=""
        ;;
esac

# Apply mode defaults for --points
if [[ -z "$CAP_POINTS" ]]; then
    case "$CAP_MODE" in
        direct) CAP_POINTS="VnicRx,VnicTx,ENSInput,Drop" ;;
        # UplinkRcvKernel/UplinkSndKernel (VMkernel/NIC boundary) is the most
        # reliable for ENS environments and L2 protocols like PROFINET.
        # UplinkRcv/UplinkSnd (DVS portset level) sits above ENS and will miss
        # ENS fast-path traffic. Use --points UplinkRcv,UplinkSnd to override.
        # If UplinkRcvKernel produces no traffic, confirm with:
        #   pktcap-uw --capture UplinkRcvKernel --uplink vmnicX -e -c 10 -o -
        # UplinkRcvKernel0 (with suffix) is NOT a valid capture point on ESXi.
        uplink) CAP_POINTS="UplinkRcvKernel,UplinkSndKernel" ;;
    esac
fi

# Cross-mode warnings
[[ -n "$ETHTYPE"    && "$CAP_MODE" == "api" ]] && warn "--ethtype is not used in api mode."
[[ -n "$PROTO"      && "$CAP_MODE" == "api" ]] && warn "--proto is not used in api mode."
[[ -n "$IP_FILTER"  && "$CAP_MODE" == "api" ]] && warn "--ip is not used in api mode (use --src / --dst instead)."
[[ -n "$RCF_FILTER" && "$CAP_MODE" == "api" ]] && warn "--rcf is not used in api mode."
[[ ( -n "$SRC_IP" || -n "$DST_IP" ) && "$CAP_MODE" != "api" ]] && warn "--src / --dst IP filters are only applied in api mode."

# Guardrail: warn on high packet count or long duration
if [[ "$CAP_MODE" != "api" ]]; then
    NUM_POINTS=$(echo "${CAP_POINTS:-1}" | tr ',' '\n' | wc -l | tr -d ' ')
    EST_MB=$(( CAP_AMOUNT * CAP_SNAPLEN * NUM_POINTS / 1024 / 1024 ))
    if [[ "$CAP_AMOUNT" -gt 5000 ]]; then
        warn "--amount ${CAP_AMOUNT} × ${NUM_POINTS} capture point(s) × ${CAP_SNAPLEN}B snaplen ≈ ${EST_MB} MB of capture data."
    fi
    if [[ "$CAP_DURATION" -gt 300 ]]; then
        warn "--duration ${CAP_DURATION}s is longer than 5 minutes. Consider using a shorter window with filters."
    fi
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SAFE_VM="${VM_NAME//[^a-zA-Z0-9_-]/_}"
SAFE_MAC="${MAC_ADDRESS//:/-}"

mkdir -p "$OUTPUT_DIR" || die "Cannot create output directory: ${OUTPUT_DIR}"

echo ""
echo -e "${BOLD}======================================================${NC}"
echo    "  nsx-pktcap-multimode"
echo    "  Mode    : ${CAP_MODE}"
[[ -n "$VM_NAME"     ]] && echo "  VM      : ${VM_NAME}"
[[ -n "$MAC_ADDRESS" ]] && echo "  MAC     : ${MAC_ADDRESS}"
[[ -n "$HOST_ARG"    ]] && echo "  Host    : ${HOST_ARG}"
[[ -n "$UPLINK_NIC"  ]] && echo "  Uplink  : ${UPLINK_NIC}"
[[ -n "$VMK_NIC"     ]] && echo "  VMk     : ${VMK_NIC}"
[[ "$CAP_MODE" != "api" && "$CAP_MODE" != "vmk" ]] && echo "  Points  : ${CAP_POINTS}"
[[ -n "$ETHTYPE"     ]] && echo "  EthType : ${ETHTYPE}"
[[ -n "$PROTO"       ]] && echo "  Proto   : ${PROTO}"
[[ -n "$IP_FILTER"   ]] && echo "  IP      : ${IP_FILTER}"
[[ -n "$RCF_FILTER"  ]] && echo "  RCF     : ${RCF_FILTER}"
[[ -n "$SRC_IP"      ]] && echo "  Src IP  : ${SRC_IP}"
[[ -n "$DST_IP"      ]] && echo "  Dst IP  : ${DST_IP}"
[[ -n "$SRC_MAC"     ]] && echo "  Src MAC : ${SRC_MAC}"
[[ -n "$DST_MAC"     ]] && echo "  Dst MAC : ${DST_MAC}"
[[ -n "$VLAN_ID"     ]] && echo "  VLAN    : ${VLAN_ID}"
echo    "  Duration: ${CAP_DURATION}s  |  Max pkts: ${CAP_AMOUNT}  |  Snaplen: ${CAP_SNAPLEN}B"
echo -e "${BOLD}======================================================${NC}"
echo ""

# =============================================================================
# NSX / HOST LOOKUPS (conditional by mode)
# =============================================================================
HOST_ID=""; HOST_NAME=""; ESXI_HOST_IP=""
VM_UUID=""; VNIC_NAME=""
SEG_PORT_ID=""; SEG_PORT_PATH=""; SEGMENT=""

if [[ "$CAP_MODE" == "uplink" || "$CAP_MODE" == "vmk" ]]; then
    # uplink and vmk always use --host directly — no NSX lookup needed
    ESXI_HOST_IP="$HOST_ARG"
    HOST_NAME="$HOST_ARG"
    success "Using ESXi host: ${ESXI_HOST_IP}"
    echo ""

elif [[ "$CAP_MODE" == "direct" && -n "$HOST_ARG" ]]; then
    # direct with --host: bypass NSX lookup, SSH directly to the given host
    ESXI_HOST_IP="$HOST_ARG"
    HOST_NAME="$HOST_ARG"
    info "Using --host directly (skipping NSX VM lookup): ${ESXI_HOST_IP}"
    echo ""

else
    # api and direct (without --host): use NSX fabric to find the VM and host

    # Step 1 — VM fabric lookup
    info "Step 1 — Looking up VM '${VM_NAME}' in NSX fabric..."
    VM_RESP=$(nsx_curl GET "/api/v1/fabric/virtual-machines?display_name=${VM_NAME}")
    RESULT_COUNT=$(json_get "d['result_count']" "$VM_RESP")
    [[ "$RESULT_COUNT" -eq 0 ]] && die "VM '${VM_NAME}' not found in NSX fabric inventory.
  If this VM's host is not an NSX transport node, re-run with --host <ESXi_IP> to bypass the NSX lookup."
    [[ "$RESULT_COUNT" -gt 1 ]]  && warn "Multiple VMs matched '${VM_NAME}' — using the first."

    VM_UUID=$(json_get   "d['results'][0]['external_id']"                       "$VM_RESP")
    HOST_ID=$(json_get   "d['results'][0]['host_id']"                           "$VM_RESP")
    HOST_NAME=$(json_get "d['results'][0]['source']['target_display_name']"     "$VM_RESP")
    success "Found VM — host: ${HOST_NAME}"

    # Step 2 — vNIC lookup by MAC (api + direct)
    info "Step 2 — Finding vNIC with MAC ${MAC_ADDRESS}..."
    VIF_RESP=$(nsx_curl GET "/api/v1/fabric/vifs?owner_vm_id=${VM_UUID}")
    LPORT_ATTACH_ID=$(python3 -c "
import json
data = json.loads('''${VIF_RESP}''')
mac = '${MAC_ADDRESS}'
for vif in data.get('results', []):
    if vif.get('mac_address','').lower() == mac:
        print(vif.get('lport_attachment_id',''))
        break
")
    VNIC_NAME=$(python3 -c "
import json
data = json.loads('''${VIF_RESP}''')
mac = '${MAC_ADDRESS}'
for vif in data.get('results', []):
    if vif.get('mac_address','').lower() == mac:
        print(vif.get('device_name','unknown'))
        break
")

    if [[ -z "$VNIC_NAME" ]]; then
        die "No vNIC found with MAC '${MAC_ADDRESS}' on VM '${VM_NAME}'."
    fi
    success "Found vNIC '${VNIC_NAME}'"

    # Step 3 — Segment Port lookup (api only; direct mode skips this)
    if [[ "$CAP_MODE" == "api" ]]; then
        [[ -z "$LPORT_ATTACH_ID" ]] && \
            die "vNIC '${VNIC_NAME}' has no NSX segment port attachment.
  This vNIC is not connected to an NSX segment — api mode requires an NSX segment port.
  Use --mode direct instead to capture via SSH."

        info "Step 3 — Resolving NSX Segment Port..."
        SEARCH_RESP=$(nsx_curl GET \
            "/policy/api/v1/search?query=resource_type:SegmentPort%20AND%20attachment.id:${LPORT_ATTACH_ID}")
        PORT_COUNT=$(json_get "d['result_count']" "$SEARCH_RESP")
        [[ "$PORT_COUNT" -eq 0 ]] && \
            die "No NSX Segment Port found for attachment '${LPORT_ATTACH_ID}'.
  This vNIC may be on a DVS port group that is not an NSX segment.
  Use --mode direct instead."

        SEG_PORT_ID=$(json_get   "d['results'][0]['unique_id']"   "$SEARCH_RESP")
        SEG_PORT_PATH=$(json_get "d['results'][0]['path']"        "$SEARCH_RESP")
        SEGMENT=$(json_get       "d['results'][0]['parent_path']" "$SEARCH_RESP")
        success "Segment Port: ${SEG_PORT_ID}"
        info    "  Path    : ${SEG_PORT_PATH}"
        info    "  Segment : ${SEGMENT}"
    fi

    # Resolve HOST_ID → ESXI_HOST_IP for direct mode (without --host)
    if [[ "$CAP_MODE" == "direct" ]]; then
        info "Resolving ESXi host IP for '${HOST_NAME}'..."
        ESXI_HOST_IP=$(resolve_host_ip "$HOST_ID")
        [[ -z "$ESXI_HOST_IP" ]] && \
            die "Could not resolve ESXi host IP for host_id '${HOST_ID}'.
  Try re-running with --host <ESXi_IP> to specify the host IP directly."
        success "ESXi host IP: ${ESXI_HOST_IP}"
    fi
fi

echo ""

# =============================================================================
# BRANCH BY MODE
# =============================================================================

if [[ "$CAP_MODE" == "api" ]]; then

    # -------------------------------------------------------------------------
    # API MODE — NSX Policy API SEGMENTPORT capture
    # -------------------------------------------------------------------------
    # Captures at the DVS logical port boundary (PortInput / PortOutput).
    # Will NOT capture:
    #   • ENS fast-path traffic (bypasses PortInput entirely)
    #   • L2-only multicast (PROFINET 0x8892, PTP 0x88f7) — arrives at VnicRx
    #     downstream of PortInput, invisible from SEGMENTPORT
    #   • VMs not attached to an NSX segment
    # Use --mode direct for those cases.
    # -------------------------------------------------------------------------

    info "Starting NSX API capture session..."
    info "  Transport node : ${HOST_NAME}"
    info "  Direction      : ${CAP_DIRECTION}"
    info "  Duration       : ${CAP_DURATION}s  |  Max packets: ${CAP_AMOUNT}"
    [[ -n "$SRC_IP" ]] && info "  Filter SRC IP  : ${SRC_IP}"
    [[ -n "$DST_IP" ]] && info "  Filter DST IP  : ${DST_IP}"

    OPTIONS_JSON=$(python3 -c "
import json
opts = []
src, dst = '${SRC_IP}', '${DST_IP}'
if src: opts.append({'name': 'SRCIP', 'value': src})
if dst: opts.append({'name': 'DSTIP', 'value': dst})
print(json.dumps({'values': opts}) if opts else '')
")

    if [[ -n "$OPTIONS_JSON" ]]; then
        REQUEST_BODY="{
            \"node\":        \"${HOST_ID}\",
            \"capsource\":   \"CLI\",
            \"cappoint\":    \"SEGMENTPORT\",
            \"capvalue\":    \"${SEG_PORT_ID}\",
            \"direction\":   \"${CAP_DIRECTION}\",
            \"capmode\":     \"STANDALONE\",
            \"capduration\": ${CAP_DURATION},
            \"capamount\":   ${CAP_AMOUNT},
            \"capsnaplen\":  ${CAP_SNAPLEN},
            \"options\":     ${OPTIONS_JSON}
        }"
    else
        REQUEST_BODY="{
            \"node\":        \"${HOST_ID}\",
            \"capsource\":   \"CLI\",
            \"cappoint\":    \"SEGMENTPORT\",
            \"capvalue\":    \"${SEG_PORT_ID}\",
            \"direction\":   \"${CAP_DIRECTION}\",
            \"capmode\":     \"STANDALONE\",
            \"capduration\": ${CAP_DURATION},
            \"capamount\":   ${CAP_AMOUNT},
            \"capsnaplen\":  ${CAP_SNAPLEN}
        }"
    fi

    CREATE_RESP=$(nsx_curl POST "/policy/api/v1/infra/pktcap/session" -d "$REQUEST_BODY")
    SESSION_ID=$(json_get "d['sessionid']" "$CREATE_RESP")
    success "Capture session created — ID: ${SESSION_ID}"
    echo ""
    warn "Capture running for up to ${CAP_DURATION}s on '${VNIC_NAME}' (${MAC_ADDRESS})."
    warn "Generate traffic on the VM now if needed..."
    echo ""

    POLL_INTERVAL=5
    MAX_POLLS=$(( (CAP_DURATION + 30) / POLL_INTERVAL ))
    FINAL_STATUS=""; FILE_SIZE=0
    for (( i=1; i<=MAX_POLLS; i++ )); do
        sleep "$POLL_INTERVAL"
        POLL_RESP=$(nsx_curl GET "/policy/api/v1/infra/pktcap/session/${SESSION_ID}")
        FINAL_STATUS=$(json_get "d['sessionstatus']" "$POLL_RESP")
        FILE_SIZE=$(python3 -c "import json; d=json.loads('''${POLL_RESP}'''); print(d.get('filesize',0))")
        printf "  [%2ds] status = %s  |  file size = %s bytes\n" \
            $(( i * POLL_INTERVAL )) "$FINAL_STATUS" "$FILE_SIZE"
        [[ "$FINAL_STATUS" == "FINISHED" || "$FINAL_STATUS" == "STOPPED" || "$FINAL_STATUS" == "ERROR" ]] && break
    done

    [[ "$FINAL_STATUS" == "ERROR" ]] && \
        die "Capture ended with ERROR: $(json_get "d.get('errormsg','unknown')" "$POLL_RESP")"
    [[ "$FINAL_STATUS" != "FINISHED" && "$FINAL_STATUS" != "STOPPED" ]] && \
        die "Session did not finish within expected time (status: ${FINAL_STATUS})."

    echo ""
    success "Capture complete — ${FILE_SIZE} bytes."

    PCAP_FILE="${OUTPUT_DIR}/${SAFE_VM}_${SAFE_MAC}_${TIMESTAMP}.pcap"
    info "Downloading .pcap file..."
    HTTP_CODE=$(curl -sk \
        -u "${NSX_USER}:${NSX_PASS}" \
        -H "Accept: application/octet-stream" \
        -o "$PCAP_FILE" -w "%{http_code}" \
        "${NSX_MGR}/policy/api/v1/infra/pktcap/session/${SESSION_ID}/CapturedFile")
    [[ "$HTTP_CODE" -ne 200 ]] && die "Download failed [HTTP ${HTTP_CODE}]."
    ACTUAL_SIZE=$(wc -c < "$PCAP_FILE" | tr -d ' ')
    success "Downloaded: ${PCAP_FILE} (${ACTUAL_SIZE} bytes)"

    nsx_curl DELETE "/policy/api/v1/infra/pktcap/session/${SESSION_ID}" > /dev/null
    success "Session ${SESSION_ID} deleted from NSX."

    echo ""
    echo "======================================================"
    echo "  Capture Complete (api / SEGMENTPORT)"
    echo "  VM            : ${VM_NAME}"
    echo "  vNIC          : ${VNIC_NAME} (${MAC_ADDRESS})"
    echo "  Transport node: ${HOST_NAME}"
    [[ -n "$SRC_IP" ]] && echo "  Filter SRC IP : ${SRC_IP}"
    [[ -n "$DST_IP" ]] && echo "  Filter DST IP : ${DST_IP}"
    echo "  File          : ${PCAP_FILE} (${ACTUAL_SIZE} bytes)"
    echo "======================================================"
    echo ""
    info "Open in Wireshark or run: tcpdump -r '${PCAP_FILE}' -n -v"
    echo ""

elif [[ "$CAP_MODE" == "direct" ]]; then

    # -------------------------------------------------------------------------
    # DIRECT MODE — SSH to ESXi + parallel pktcap-uw on the VM's switchport
    # -------------------------------------------------------------------------
    # Works for any VM on the host, regardless of NSX segment attachment.
    # If --host is supplied, the NSX VM lookup is skipped entirely.
    #
    # Capture points:
    #   VnicRx   — frame arriving at the VM vNIC driver. Primary delivery
    #              confirmation; catches ENS slow-path multicast that
    #              PortInput/SEGMENTPORT miss.
    #   VnicTx   — frame leaving the VM vNIC driver. Confirms VM is sending.
    #   ENSInput — frame entering ENS from the VM transmit side (vSwitch view).
    #              Catches ENS fast-path frames that bypass VnicTx.
    #   Drop     — frames dropped by the vSwitch at this port. Reveals silent
    #              discards from missing mcast_filter entries or L2 security.
    # -------------------------------------------------------------------------

    command -v sshpass &>/dev/null || die "'sshpass' not found. Install it or configure SSH key auth."
    check_ssh_connectivity

    info "Finding ESXi switchport ID for MAC ${MAC_ADDRESS} on ${ESXI_HOST_IP}..."
    PORT_INFO=$(esxi_ssh "
        wid=\$(esxcli network vm list 2>/dev/null | grep -i '${VM_NAME}' | awk '{print \$1}' | head -1)
        if [[ -n \"\$wid\" ]]; then
            esxcli network vm port list -w \"\$wid\" 2>/dev/null
        fi
    ") || true

    SWITCH_PORT_ID=$(python3 -c "
import re
mac = '${MAC_ADDRESS}'.lower()
cur_port = ''
for line in '''${PORT_INFO}'''.splitlines():
    m = re.match(r'\s*Port ID:\s*(\d+)', line)
    if m:
        cur_port = m.group(1)
    if re.search(r'\b' + re.escape(mac) + r'\b', line.lower()):
        print(cur_port)
        break
")
    [[ -z "$SWITCH_PORT_ID" ]] && \
        die "Could not find switchport ID for MAC '${MAC_ADDRESS}' on ${ESXI_HOST_IP}."
    success "Switchport ID: ${SWITCH_PORT_ID}"

    # Guardrail: warn if pktcap-uw is already running
    check_pktcap_running

    REMOTE_DIR=$(find_vmfs_dir "${SAFE_VM}_${TIMESTAMP}") || true
    [[ -z "$REMOTE_DIR" ]] && die "Could not find a writable VMFS datastore on ${ESXI_HOST_IP}.\n  Check SSH access and verify 'df -h /vmfs/volumes/' on the host."
    success "Remote capture dir: ${REMOTE_DIR}"

    # Guardrail: ensure the datastore has enough free space
    check_vmfs_space "${REMOTE_DIR}"

    FILTER_ARGS=""
    [[ -n "$ETHTYPE"    ]] && FILTER_ARGS="${FILTER_ARGS} --ethtype ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && FILTER_ARGS="${FILTER_ARGS} --proto ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && FILTER_ARGS="${FILTER_ARGS} --ip ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && FILTER_ARGS="${FILTER_ARGS} --srcmac ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && FILTER_ARGS="${FILTER_ARGS} --dstmac ${DST_MAC}"
    # --rcf wraps the expression in single quotes to preserve spaces on the remote host
    [[ -n "$RCF_FILTER" ]] && FILTER_ARGS="${FILTER_ARGS} --rcf '${RCF_FILTER}'"

    info "Launching parallel pktcap-uw at: ${CAP_POINTS}"
    [[ -n "$ETHTYPE"    ]] && info "  EtherType filter: ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && info "  Proto filter    : ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && info "  IP filter       : ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && info "  Src MAC filter  : ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && info "  Dst MAC filter  : ${DST_MAC}"
    [[ -n "$RCF_FILTER" ]] && info "  RCF filter      : ${RCF_FILTER}"
    echo ""

    launch_captures \
        "$REMOTE_DIR" \
        "$FILTER_ARGS" \
        "$CAP_POINTS" \
        "${SAFE_VM}_${SAFE_MAC}" \
        "--switchport ${SWITCH_PORT_ID}"

    wait_and_collect "${SAFE_VM}_${SAFE_MAC}"

    esxi_ssh "rm -rf \"${REMOTE_DIR}\" 2>/dev/null || true" || true
    success "Remote files cleaned up."

    echo ""
    echo "======================================================"
    echo "  Capture Complete (direct / VM switchport)"
    [[ -n "$VNIC_NAME" ]] && echo "  VM      : ${VM_NAME} — ${VNIC_NAME} (${MAC_ADDRESS})" \
                          || echo "  VM      : ${VM_NAME} (${MAC_ADDRESS})"
    echo "  Host    : ${ESXI_HOST_IP}"
    echo "  Port ID : ${SWITCH_PORT_ID}"
    [[ -n "$ETHTYPE"    ]] && echo "  EthType : ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && echo "  Proto   : ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && echo "  IP      : ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && echo "  Src MAC : ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && echo "  Dst MAC : ${DST_MAC}"
    [[ -n "$RCF_FILTER" ]] && echo "  RCF     : ${RCF_FILTER}"
    echo "  Duration: ${CAP_DURATION}s  |  Snaplen: ${CAP_SNAPLEN} bytes"
    echo "  Points captured:"
    for entry in "${DOWNLOADED[@]}"; do
        printf "    %-12s %s\n" "${entry%%:*}" "${entry##*:}"
    done
    echo "======================================================"
    echo ""
    info "Open in Wireshark or run:"
    for entry in "${DOWNLOADED[@]}"; do
        printf "  tcpdump -r '%s' -nn -e   # %s\n" "${entry##*:}" "${entry%%:*}"
    done
    echo ""

elif [[ "$CAP_MODE" == "uplink" ]]; then

    # -------------------------------------------------------------------------
    # UPLINK MODE — SSH to ESXi + parallel pktcap-uw on a physical vmnic
    # -------------------------------------------------------------------------
    # Default capture points: UplinkRcvKernel,UplinkSndKernel
    # These sit at the VMkernel/NIC driver boundary — one layer below the DVS
    # portset. This is the most reliable level for ENS environments and L2
    # protocols (PROFINET, PTP) that bypass DVS portset processing.
    #
    # If UplinkRcvKernel produces no output on multi-queue NICs, try the
    # explicit queue-zero variant:
    # Note: UplinkRcv/UplinkSnd are valid but marked obsoleted by VMware and
    # sit above ENS — they will miss ENS fast-path (PROFINET, PTP) traffic.
    #
    # To capture at the DVS portset level instead (above ENS):
    #   --points UplinkRcv,UplinkSnd
    #
    # To capture at the raw NIC driver level (closest to wire), run manually:
    #   pktcap-uw --uplink vmnicX --dir 2 [filters] -e -o /vmfs/.../file.pcap
    #
    # Common filter combinations:
    #   --proto  0x6                       TCP only
    #   --proto  0x11                      UDP only
    #   --proto  0x1                       ICMP only
    #   --ip     <IP>                      Traffic to or from a specific host
    #   --dstmac <VM_MAC>                  Unicast frames destined for a specific VM
    #   --vlan   <N>                       Narrow to one VLAN on a trunk uplink
    #   --ethtype 0x8892                   PROFINET (L2-only; bypasses IP filters)
    #   --ethtype 0x88f7                   PTP
    #   --ethtype 0x0806                   ARP
    # -------------------------------------------------------------------------

    command -v sshpass &>/dev/null || die "'sshpass' not found. Install it or configure SSH key auth."
    check_ssh_connectivity

    # Guardrail: no filters on an uplink = ALL traffic on that NIC
    if [[ -z "$ETHTYPE" && -z "$PROTO" && -z "$IP_FILTER" && \
          -z "$SRC_MAC"  && -z "$DST_MAC" && -z "$VLAN_ID" && -z "$RCF_FILTER" ]]; then
        confirm "No filters set for uplink mode — this will capture ALL traffic on ${UPLINK_NIC}.\n  On a 10GbE NIC this can easily exceed 10,000 packets/second and fill the VMFS datastore.\n  Add --ethtype, --proto, --ip, --vlan, or other filters to narrow the capture.\n  Pass --yes to skip this prompt."
    fi

    # Guardrail: validate the uplink NIC exists on the host
    info "Validating uplink '${UPLINK_NIC}' on ${ESXI_HOST_IP}..."
    check_uplink_exists "${UPLINK_NIC}"

    # Guardrail: warn if pktcap-uw is already running
    check_pktcap_running

    REMOTE_DIR=$(find_vmfs_dir "uplink_${UPLINK_NIC}_${TIMESTAMP}") || true
    [[ -z "$REMOTE_DIR" ]] && die "Could not find a writable VMFS datastore on ${ESXI_HOST_IP}.\n  Check SSH access and verify 'df -h /vmfs/volumes/' on the host."
    success "Remote capture dir: ${REMOTE_DIR}"

    # Guardrail: ensure the datastore has enough free space
    check_vmfs_space "${REMOTE_DIR}"

    FILTER_ARGS=""
    [[ -n "$ETHTYPE"    ]] && FILTER_ARGS="${FILTER_ARGS} --ethtype ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && FILTER_ARGS="${FILTER_ARGS} --proto ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && FILTER_ARGS="${FILTER_ARGS} --ip ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && FILTER_ARGS="${FILTER_ARGS} --srcmac ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && FILTER_ARGS="${FILTER_ARGS} --dstmac ${DST_MAC}"
    [[ -n "$VLAN_ID"    ]] && FILTER_ARGS="${FILTER_ARGS} --vlan ${VLAN_ID}"
    [[ -n "$RCF_FILTER" ]] && FILTER_ARGS="${FILTER_ARGS} --rcf '${RCF_FILTER}'"

    FILE_LABEL="uplink_${UPLINK_NIC}"

    info "Launching parallel pktcap-uw on uplink ${UPLINK_NIC} (${ESXI_HOST_IP})..."
    info "  Capture points : ${CAP_POINTS}"
    [[ -n "$ETHTYPE"    ]] && info "  EthType filter  : ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && info "  Proto filter    : ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && info "  IP filter       : ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && info "  Src MAC filter  : ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && info "  Dst MAC filter  : ${DST_MAC}"
    [[ -n "$VLAN_ID"    ]] && info "  VLAN filter     : ${VLAN_ID}"
    [[ -n "$RCF_FILTER" ]] && info "  RCF filter      : ${RCF_FILTER}"
    echo ""

    launch_captures \
        "$REMOTE_DIR" \
        "$FILTER_ARGS" \
        "$CAP_POINTS" \
        "$FILE_LABEL" \
        "--uplink ${UPLINK_NIC}"

    wait_and_collect "$FILE_LABEL"

    esxi_ssh "rm -rf \"${REMOTE_DIR}\" 2>/dev/null || true" || true
    success "Remote files cleaned up."

    echo ""
    echo "======================================================"
    echo "  Capture Complete (uplink / physical wire)"
    echo "  Host    : ${ESXI_HOST_IP}"
    echo "  Uplink  : ${UPLINK_NIC}"
    [[ -n "$ETHTYPE"    ]] && echo "  EthType : ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && echo "  Proto   : ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && echo "  IP      : ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && echo "  Src MAC : ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && echo "  Dst MAC : ${DST_MAC}"
    [[ -n "$VLAN_ID"    ]] && echo "  VLAN    : ${VLAN_ID}"
    [[ -n "$RCF_FILTER" ]] && echo "  RCF     : ${RCF_FILTER}"
    echo "  Duration: ${CAP_DURATION}s  |  Snaplen: ${CAP_SNAPLEN} bytes"
    echo "  Points captured:"
    for entry in "${DOWNLOADED[@]}"; do
        printf "    %-12s %s\n" "${entry%%:*}" "${entry##*:}"
    done
    echo "======================================================"
    echo ""
    info "Open in Wireshark or run:"
    for entry in "${DOWNLOADED[@]}"; do
        printf "  tcpdump -r '%s' -nn -e   # %s\n" "${entry##*:}" "${entry%%:*}"
    done
    echo ""

elif [[ "$CAP_MODE" == "vmk" ]]; then

    # -------------------------------------------------------------------------
    # VMK MODE — SSH to ESXi + pktcap-uw on a VMkernel NIC
    # -------------------------------------------------------------------------
    # Captures traffic on a VMkernel interface (vmk0, vmk1, etc.).
    # VMkernel NICs carry:
    #   vmk0  — host management traffic
    #   vmk1+ — vMotion, vSAN, NFS, iSCSI, or other host-side traffic
    #
    # pktcap-uw syntax for vmk: --vmk <vmkN> --dir <0|1|2>
    #   --dir 0 = Rx only (inbound to VMkernel)
    #   --dir 1 = Tx only (outbound from VMkernel)
    #   --dir 2 = both directions (default used by this script)
    #
    # Note: vmk captures do NOT use --capture points. Direction is controlled
    # by --dir. This mode always runs as a single bidirectional capture.
    #
    # Filters supported: --ethtype, --proto, --srcmac, --dstmac, --vlan
    # -------------------------------------------------------------------------

    command -v sshpass &>/dev/null || die "'sshpass' not found. Install it or configure SSH key auth."
    check_ssh_connectivity

    # Guardrail: validate the vmk interface exists on the host
    info "Validating VMkernel interface '${VMK_NIC}' on ${ESXI_HOST_IP}..."
    check_vmk_exists "${VMK_NIC}"

    # Guardrail: warn if pktcap-uw is already running
    check_pktcap_running

    REMOTE_DIR=$(find_vmfs_dir "vmk_${VMK_NIC}_${TIMESTAMP}") || true
    [[ -z "$REMOTE_DIR" ]] && die "Could not find a writable VMFS datastore on ${ESXI_HOST_IP}.\n  Check SSH access and verify 'df -h /vmfs/volumes/' on the host."
    success "Remote capture dir: ${REMOTE_DIR}"

    # Guardrail: ensure the datastore has enough free space
    check_vmfs_space "${REMOTE_DIR}"

    FILTER_ARGS=""
    [[ -n "$ETHTYPE"    ]] && FILTER_ARGS="${FILTER_ARGS} --ethtype ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && FILTER_ARGS="${FILTER_ARGS} --proto ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && FILTER_ARGS="${FILTER_ARGS} --ip ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && FILTER_ARGS="${FILTER_ARGS} --srcmac ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && FILTER_ARGS="${FILTER_ARGS} --dstmac ${DST_MAC}"
    [[ -n "$VLAN_ID"    ]] && FILTER_ARGS="${FILTER_ARGS} --vlan ${VLAN_ID}"
    [[ -n "$RCF_FILTER" ]] && FILTER_ARGS="${FILTER_ARGS} --rcf '${RCF_FILTER}'"

    REMOTE_PCAP="${REMOTE_DIR}/vmk_${VMK_NIC}.pcapng"
    LOCAL_PCAP="${OUTPUT_DIR}/vmk_${VMK_NIC}_${TIMESTAMP}.pcapng"

    info "Launching pktcap-uw on ${VMK_NIC} (${ESXI_HOST_IP})..."
    [[ -n "$ETHTYPE"    ]] && info "  EthType filter  : ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && info "  Proto filter    : ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && info "  IP filter       : ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && info "  Src MAC filter  : ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && info "  Dst MAC filter  : ${DST_MAC}"
    [[ -n "$VLAN_ID"    ]] && info "  VLAN filter     : ${VLAN_ID}"
    [[ -n "$RCF_FILTER" ]] && info "  RCF filter      : ${RCF_FILTER}"
    echo ""

    # NOTE: -G is not valid for pktcap-uw. Duration is controlled by sleep+kill below.
    # -s sets the snaplen (bytes per packet; 0 = full packet).
    CMD="pktcap-uw --vmk ${VMK_NIC} --dir 2 ${FILTER_ARGS} -e -s ${CAP_SNAPLEN} -o \"${REMOTE_PCAP}\" -c ${CAP_AMOUNT} >/dev/null 2>&1 &"
    esxi_ssh "eval '$CMD'" || true
    success "  Started vmk capture → ${REMOTE_PCAP}"

    echo ""
    warn "Capture running for ${CAP_DURATION}s on ${VMK_NIC}. Generate traffic now if needed..."

    for (( t=0; t<CAP_DURATION; t+=10 )); do
        sleep 10
        remaining=$(( CAP_DURATION - t - 10 ))
        [[ $remaining -gt 0 ]] && printf "  %3ds remaining...\n" "$remaining"
    done

    info "Stopping captures..."
    esxi_ssh "kill \$(lsof 2>/dev/null | grep pktcap-uw | awk '{print \$1}' | sort -u) 2>/dev/null || true" || true
    sleep 2
    success "Capture stopped."

    echo ""
    info "Downloading .pcap file..."
    FILE_SIZE=$(esxi_ssh "wc -c < \"${REMOTE_PCAP}\" 2>/dev/null || echo 0" | tr -d ' \n') || true

    if [[ "${FILE_SIZE:-0}" -gt 24 ]]; then
        esxi_scp "$REMOTE_PCAP" "$LOCAL_PCAP"
        ACTUAL_SIZE=$(wc -c < "$LOCAL_PCAP" | tr -d ' ')
        success "Downloaded: ${LOCAL_PCAP} (${ACTUAL_SIZE} bytes)"
    else
        warn "Capture file is empty — no packets matched the filter on ${VMK_NIC}."
        LOCAL_PCAP=""
    fi

    esxi_ssh "rm -rf \"${REMOTE_DIR}\" 2>/dev/null || true" || true
    success "Remote files cleaned up."

    echo ""
    echo "======================================================"
    echo "  Capture Complete (vmk / VMkernel interface)"
    echo "  Host      : ${ESXI_HOST_IP}"
    echo "  Interface : ${VMK_NIC}  (bidirectional, --dir 2)"
    [[ -n "$ETHTYPE"    ]] && echo "  EthType   : ${ETHTYPE}"
    [[ -n "$PROTO"      ]] && echo "  Proto     : ${PROTO}"
    [[ -n "$IP_FILTER"  ]] && echo "  IP        : ${IP_FILTER}"
    [[ -n "$SRC_MAC"    ]] && echo "  Src MAC   : ${SRC_MAC}"
    [[ -n "$DST_MAC"    ]] && echo "  Dst MAC   : ${DST_MAC}"
    [[ -n "$VLAN_ID"    ]] && echo "  VLAN      : ${VLAN_ID}"
    [[ -n "$RCF_FILTER" ]] && echo "  RCF       : ${RCF_FILTER}"
    echo "  Duration  : ${CAP_DURATION}s  |  Snaplen: ${CAP_SNAPLEN} bytes"
    [[ -n "$LOCAL_PCAP" ]] && echo "  File      : ${LOCAL_PCAP} (${ACTUAL_SIZE} bytes)"
    echo "======================================================"
    echo ""
    [[ -n "$LOCAL_PCAP" ]] && { info "Open in Wireshark or run:"; echo "  tcpdump -r '${LOCAL_PCAP}' -nn -e -v   # (pcapng format — Wireshark recommended)"; echo ""; }

fi
