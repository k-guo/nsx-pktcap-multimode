# nsx-pktcap-multimode — NSX / ESXi Multi-Mode Packet Capture

Run multi-point `pktcap-uw` packet captures on an ESXi host directly from your laptop — no need to SSH in manually or memorise capture point syntax. The script abstracts the complexity: launching parallel captures across multiple points simultaneously, waiting out the capture window, downloading the `.pcapng` files to your local machine, and cleaning up after itself.

Supports four modes: **NSX Policy API** (no SSH required, VM must be on a VPC or NSX segment), **direct** SSH to the ESXi host and captures on VM switchport, **physical uplink**, and **VMkernel interface**. Built with production guardrails — checks for SSH connectivity, interface existence, VMFS free space, and warns before launching unfiltered captures on high-traffic uplinks.

## Capture modes

| Mode | Where it captures | Requirements | Best for |
|---|---|---|---|
| `api` | NSX SEGMENTPORT (DVS logical port boundary) | VM on NSX segment | Standard IP/TCP/UDP; no SSH needed |
| `direct` | VM switchport — `VnicRx`, `VnicTx`, `ENSInput`, `Drop` **in parallel** | VM on any ESXi host | PROFINET, PTP, L2 multicast, drops; works without NSX segment |
| `uplink` | Physical vmnic — `UplinkRcvKernel` + `UplinkSndKernel` **simultaneously** | `--host` + `--uplink` | Wire-level: confirms traffic arrives/leaves the host, unicast to a specific VM MAC |
| `vmk` | VMkernel NIC (`--vmk vmk0`) | `--host` + `--vmk` | Management, vMotion, vSAN, NFS traffic |

### Capture point stack

```
Physical wire
  ↕  NIC driver
[ --uplink vmnicX --dir 2 ]          raw NIC level (hardware wiretap)
  ↕  VMkernel boundary
[ UplinkRcvKernel / UplinkSndKernel ]  VMkernel ↔ NIC driver
  ↕  DVS portset
[ UplinkRcv / UplinkSnd ]            DVS portset  ← default for uplink mode
  ↕  DVS logical port
[ PortInput / PortOutput ]           = SEGMENTPORT in NSX API
  ↕  vNIC driver
[ VnicRx / VnicTx ]                  VM vNIC driver  ← default for direct mode
[ ENSInput ]                         ENS fast-path (sender view)
[ Drop ]                             dropped at vSwitch
  ↕
VM guest OS
```

> **`UplinkRcv` vs `UplinkRcvKernel`:**
> `UplinkRcv/UplinkSnd` (the default) captures at the DVS portset boundary — reliable for L2 multicast debugging.
> `UplinkRcvKernel/UplinkSndKernel` is one layer lower (VMkernel/NIC boundary) and may show NIC offload effects like LRO reassembly.
> Override with `--points UplinkRcvKernel,UplinkSndKernel` if needed.

> **`api` limitations:**
> SEGMENTPORT (= PortInput/PortOutput) is INVISIBLE to ENS fast-path traffic and L2-only multicast (PROFINET, PTP). It also requires the vNIC to be connected to an NSX segment.
> Use `--mode direct` for those cases.

## Requirements

- `bash` (macOS or Linux)
- `curl`, `python3`
- `sshpass` (direct/uplink/vmk modes — or configure SSH key auth)

## Setup

```bash
chmod +x nsx-pktcap-multimode.sh
```

Edit credentials at the top of the script:
```bash
NSX_MGR="https://<your-nsx-manager>"
NSX_USER="admin"
NSX_PASS="<password>"

ESXI_USER="root"
ESXI_PASS="<esxi-root-password>"   # direct / uplink / vmk modes
```

## Usage

```
# api / direct: VM_NAME and MAC_ADDRESS are always required
./nsx-pktcap-multimode.sh [OPTIONS] <VM_NAME> <MAC_ADDRESS>
./nsx-pktcap-multimode.sh --mode direct [--host <IP>] [OPTIONS] <VM_NAME> <MAC_ADDRESS>

# uplink: always requires --host and --uplink (not VM-specific)
./nsx-pktcap-multimode.sh --mode uplink --host <ESXi_IP> --uplink <vmnic> [OPTIONS]

# vmk: always requires --host and --vmk
./nsx-pktcap-multimode.sh --mode vmk --host <ESXi_IP> --vmk <vmkN> [OPTIONS]
```

### All options

| Flag | Default | Description |
|---|---|---|
| `--mode api\|direct\|uplink\|vmk` | `api` | Capture mode |
| `--host <IP>` | — | ESXi host IP. **Required** for uplink/vmk. **Optional** for direct (skips NSX VM lookup — use when the VM's host is not an NSX transport node) |
| `--uplink <vmnic>` | — | Physical NIC (required: uplink mode). Find with: `esxcli network vswitch dvs vmware list` |
| `--vmk <vmkN>` | — | VMkernel NIC (required: vmk mode). Find with: `esxcli network ip interface list` |
| `--ethtype <hex>` | — | EtherType filter (direct/uplink/vmk) |
| `--proto <hex>` | — | IP protocol filter: `0x1`=ICMP, `0x6`=TCP, `0x11`=UDP (direct/uplink/vmk) |
| `--ip <IP>` | — | IP address filter — matches src **or** dst (direct/uplink/vmk) |
| `--rcf <expr>` | — | Raw capture filter, e.g. `'geneve and host 10.0.0.1'` (direct/uplink/vmk). Quote the expression. Used for NSX/Geneve overlay traffic. |
| `--src <IP>` | — | Source IP filter (api only) |
| `--dst <IP>` | — | Destination IP filter (api only) |
| `--srcmac <MAC>` | — | Source MAC filter (direct/uplink/vmk) |
| `--dstmac <MAC>` | — | Destination MAC filter (direct/uplink/vmk) |
| `--vlan <N>` | — | VLAN ID filter (uplink/vmk) |
| `--duration <sec>` | `60` | Capture window in seconds |
| `--amount <n>` | `1000` | Max packets per capture point |
| `--points <list>` | see below | Comma-separated `pktcap-uw` capture points |
| `--out <dir>` | `.` | Local directory for `.pcapng` files |

**Default `--points`:**
- `direct` → `VnicRx,VnicTx,ENSInput,Drop`
- `uplink` → `UplinkRcvKernel,UplinkSndKernel` (VMkernel/NIC boundary — most reliable for ENS/PROFINET)
- `vmk` → N/A (single bidirectional capture with `--dir 2`)

---

## Capture scenarios

### 1. All traffic for a VM (api mode — no SSH needed)

NSX API captures at the DVS logical port (SEGMENTPORT). Good for standard IP/TCP/UDP traffic. The VM must be on an NSX segment.

```bash
# All traffic
./nsx-pktcap-multimode.sh my-vm 00:50:56:b2:50:c8

# Filtered by source and destination IP
./nsx-pktcap-multimode.sh --src 10.1.1.5 --dst 10.1.1.10 my-vm 00:50:56:b2:50:c8
```

---

### 2. VM vNIC — 4 capture points simultaneously (direct mode)

`direct` mode runs four `pktcap-uw` captures in parallel:

| Point | What it captures |
|---|---|
| `VnicRx` | Packets delivered to the VM's vNIC (inbound). Did the VM actually receive it? |
| `VnicTx` | Packets sent by the VM's vNIC (outbound). |
| `ENSInput` | Packets entering the ENS fast-path from the VM. |
| `Drop` | Packets dropped by the vSwitch at this port. |

```bash
# All traffic — works with or without NSX segment when --host is used
./nsx-pktcap-multimode.sh --mode direct my-vm 00:50:56:b2:50:c8

# TCP only
./nsx-pktcap-multimode.sh --mode direct --proto 0x6 my-vm 00:50:56:b2:50:c8

# PROFINET traffic (EtherType 0x8892)
./nsx-pktcap-multimode.sh --mode direct --ethtype 0x8892 ievd-vlan-107 00:50:56:a7:1a:5d

# Bypass NSX host lookup — use when VM is not on an NSX segment
# or the ESXi host is not an NSX transport node
./nsx-pktcap-multimode.sh --mode direct --host 10.1.1.203 my-vm 00:50:56:a7:bb:80
```

---

### 3. Physical uplink (uplink mode)

Captures at the VMkernel/NIC boundary (`UplinkRcvKernel,UplinkSndKernel` by default). Both directions simultaneously. Required for L2-only protocols that bypass the DVS portset.

```bash
# All traffic on VLAN 107
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 --vlan 107

# UDP traffic to/from a specific host
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --proto 0x11 --ip 10.1.1.55 --vlan 107

# Unicast to a specific VM's MAC
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --dstmac 00:50:56:a7:31:43 --vlan 107

# PROFINET traffic (EtherType 0x8892)
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --ethtype 0x8892 --vlan 107
```

If `UplinkRcvKernel` shows no output, verify manually on the ESXi host — there may simply be no matching traffic:
```bash
pktcap-uw --capture UplinkRcvKernel --uplink vmnic2 -e -c 10 -o - | tcpdump-uw -r - -nn -e
```

---

### 4. VMkernel NIC (vmk mode)

```bash
# All traffic on vmk0 (management / vMotion / vSAN / NFS)
./nsx-pktcap-multimode.sh --mode vmk --host 10.1.1.203 --vmk vmk0

# ICMP only (proto 0x1)
./nsx-pktcap-multimode.sh --mode vmk --host 10.1.1.203 --vmk vmk0 --proto 0x1

# ARP only (EtherType 0x0806)
./nsx-pktcap-multimode.sh --mode vmk --host 10.1.1.203 --vmk vmk0 --ethtype 0x0806
```

---

### Other examples

**Uplink — filter by IP address (src or dst):**
```bash
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --ip 10.1.1.55
```

**Uplink — NSX/Geneve overlay capture:**
```bash
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --rcf 'geneve and host 10.1.1.55'
```

**Direct — capture at DVS portset level instead of VMkernel boundary:**
```bash
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --points UplinkRcv,UplinkSnd --vlan 107
```

---

## Uplink capture points explained

There are three distinct layers at which `pktcap-uw` can capture uplink traffic:

| Capture point | Layer | Notes |
|---|---|---|
| `UplinkRcvKernel` / `UplinkSndKernel` (**script default**) | VMkernel/NIC boundary | Inbound/outbound at the NIC driver ↔ VMkernel boundary. Required for ENS environments and L2 protocols (PROFINET, PTP). |
| `UplinkRcv` / `UplinkSnd` | DVS portset | Valid but **marked obsoleted by VMware** (confirmed on ESXi). Sits above ENS — misses ENS fast-path traffic. Use with `--points UplinkRcv,UplinkSnd` if you specifically need portset-level captures. |
| `--uplink vmnicX --dir 2` *(manual only)* | Raw NIC driver | Closest to wire. Run manually on the ESXi host — the script uses `--capture` points instead. |

> **`UplinkRcvKernel0` is not a valid capture point.** Verified directly on ESXi: pktcap-uw returns `error: No such capture point: UplinkRcvKernel0` and prints the full list of 45 supported points — `UplinkRcvKernel0` is not among them.

---

## Capture settings

All settings have a default hardcoded at the top of the script. Most can also be overridden at runtime using CLI flags — no need to edit the script.

| Setting | Default | CLI flag | Description |
|---|---|---|---|
| `CAP_DIRECTION` | `DUAL` | *(edit script)* | `INPUT`, `OUTPUT`, or `DUAL`. NSX API mode only. Do not use `BOTH` — the NSX API requires `DUAL` for bidirectional. |
| `CAP_DURATION` | `60` | `--duration <sec>` | How long to run the capture. After this many seconds the script kills all `pktcap-uw` processes and downloads the files. |
| `CAP_AMOUNT` | `1000` | `--amount <n>` | Max packets per capture point. `pktcap-uw` also stops when this count is reached, whichever comes first. |
| `CAP_SNAPLEN` | `1500` | `--snaplen <n>` | Bytes captured per packet. `1500` covers a standard Ethernet frame. Set to `0` for full packet (jumbo frames, tunnels). Passed as `-s` to `pktcap-uw`. |
| `OUTPUT_DIR` | `.` | `--out <dir>` | Local directory where `.pcapng` files are saved. Created automatically if it does not exist. |

**Examples:**
```bash
# Shorten capture to 30s, full packet capture, save to ~/captures
./nsx-pktcap-multimode.sh --mode uplink --host 10.1.1.203 --uplink vmnic2 \
  --ethtype 0x8892 --duration 30 --snaplen 0 --out ~/captures

# Increase max packet count to 5000, save to /tmp
./nsx-pktcap-multimode.sh --mode direct --ethtype 0x8892 \
  --amount 5000 --out /tmp ievd-vlan-107 00:50:56:a7:31:43
```

`CAP_DIRECTION` can only be changed by editing the variable at the top of the script — it controls the NSX API capture direction and is not exposed as a flag since it only applies to `api` mode.

---

## Notes

- Captures are stored on a VMFS datastore (not `/tmp`) on the ESXi host during the run and deleted after download ([KB 341568](https://knowledge.broadcom.com/external/article/341568)). Output files use `.pcapng` for SSH modes (direct/uplink/vmk) and `.pcap` for api mode.
- `--vlan` is important on trunk uplinks — without it you capture all VLANs on that vmnic.
- Filters can be combined: `--ethtype 0x8892 --dstmac 00:50:56:a7:31:43 --vlan 107`.
- `--ip <IP>` is a bidirectional IP filter (matches src **or** dst). Use it to narrow a broad capture to traffic involving a specific host.
- `--rcf '<expr>'` passes a raw tcpdump-style filter to `pktcap-uw`. Useful for NSX Geneve overlay: `--rcf 'geneve and host 10.1.1.5'`. Always quote the expression.
- `vmk` mode always captures both directions (`--dir 2`). No `--points` flag is used.
- `--srcmac` and `--dstmac` work in all SSH modes (`direct`, `uplink`, `vmk`).

---

## License

MIT License

Copyright (c) 2026 NSX Packet Capture Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
