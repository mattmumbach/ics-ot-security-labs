# Modbus/TCP detection lab: simulated control network, Zeek detections

Simulated lab, not plant experience. Built 2026-11-20 on an Apple Silicon Mac with Docker Desktop
and Zeek 9.0.1. The PLC simulator and the Zeek script were written with an AI coding assistant
(Claude Code); I designed the tests, ran every step, predicted and checked each result.

## What was built

One Docker bridge network, 172.20.0.0/24, with four hosts running the same small Python Modbus/TCP
code (standard library only):

| Host | IP | Role |
|---|---|---|
| PLC | 172.20.0.10 | Modbus/TCP server on port 502, 10 holding registers. Register 0 is the process setpoint, safe range 40-60. No authentication and no range check, like many real PLCs. |
| HMI | 172.20.0.20 | Operator screen: reads the setpoint (FC 3) every 2 seconds over one long-lived connection. |
| EWS | 172.20.0.30 | Engineering workstation: the only host allowed to write. |
| Attacker | 172.20.0.66 | A host on the control network that should never send commands. |

Capture: tcpdump in a sidecar container sharing the PLC's network interface (`network_mode:
service:plc`), filter `port 502`, one pcap per scenario. Docker Desktop on macOS runs containers in a
Linux VM, so the bridge is not visible from the Mac; the sidecar plays the role of a SPAN port.

Analysis: Zeek 9.0.1 (official `zeek/zeek` image) read each pcap offline with a detection script
([`lab/zeek/detect.zeek`](lab/zeek/detect.zeek)) using Zeek's built-in Modbus analyzer and the Notice framework. Event names were
checked against the installed version's `Zeek_Modbus.events.bif.zeek` before writing the script.

## Detections

| ID | Name | Rule |
|---|---|---|
| D1 | Unauthorized Modbus write | A write function code (5, 6, 15, 16, 21, 22, 23) from any host other than the EWS |
| D2 | Unsafe setpoint | A write (FC 6, or FC 16 covering register 0) that sets register 0 outside 40-60, from any host |
| D3 | Recon | Read Device Identification (FC 43, MEI type 14) from any host other than the EWS |

D1 checks who is writing; D2 checks what was written. Each covers the other's blind spot: D1 misses
a trusted host doing something dangerous, D2 misses quiet in-range changes.

## Results

All times local (EST); Zeek timestamps are UTC epoch seconds.

| Scenario | What happened | Packets | D1 | D2 | D3 |
|---|---|---|---|---|---|
| Baseline | 22.5 min (10:38-11:00): 674 HMI polls, 3 EWS writes (48 at 10:39:42, 55 at 10:53:29, 50 at 10:58:07) | 2052 | - | - | - |
| A1 | Attacker writes 45 (in range) at 11:15:56 | 334 | fired | - | - |
| A2 | Attacker writes 95 (unsafe) at 11:22:47 | 277 | fired | fired | - |
| A3 | Attacker reads device ID at 14:47:45; PLC returned vendor, product code, firmware revision | 250 | - | - | fired |
| A4 | EWS writes 75 (engineer typo for 57) at 14:53:59 | 151 | - | fired | - |

Every scenario produced exactly the expected alerts and no others. The baseline's silence is a real
pass, not a blind spot: Zeek's `modbus.log` for the baseline shows all three legitimate EWS writes
(`WRITE_SINGLE_REGISTER` from 172.20.0.30), and D1 correctly ignored them. The PLC accepted every
write, including 95 and 75, because nothing in Modbus or this PLC checks the sender or the value.

## Limits

This lab is deliberately small: one PLC, one HMI, one engineering workstation and one attacker. A
real plant has many field devices and several controllers, often of different kinds and vendors,
plus SCADA, DCS or process control systems around them. So the lab is a demonstration of how a PLC
is designed, how it can be misused and how that shows up on the network, not a model of a plant.

A real plant should also have controls this lab leaves out on purpose: a firewall limiting which
hosts can reach the controllers, and some form of authentication or approval before sensitive
changes are made.

D1 trusts the source IP address and nothing else. Anything running on the engineering workstation
passes it, and an attacker on the same network segment can take over the workstation's address,
for example with ARP spoofing. A4 showed that D2 still catches a dangerous value from the trusted
address, but a quiet, in-range change from a spoofed or compromised workstation would pass both.

The baseline was 22 minutes and the rules were written by hand for one register. A real plant has
shift changes, maintenance windows, start-ups and hundreds of meaningful values. The allowed hosts
and the safe ranges would have to come from an asset inventory and from the process engineers, and
the baseline would need to cover weeks, not minutes.

## What I would do first in a real plant

Before writing any alert, I would learn the environment: review or take a passive baseline of the
traffic, learn the process from maintenance and operations, and build or validate the asset
inventory. Only then would I write alerts, tuned with the engineers. The baseline would be passive:
listening on a mirror port, with no scanning of the controllers.

## Not built in the lab, and how I would do it in production

The firewall was left out to keep the first version simple, with a plan to add it later. This lab
only detects; it does not block anything, and every attack command reached the PLC.

How I would build it in production (a design; none of this was built or measured):

- A firewall in front of the PLC that allows TCP 502 only from the HMI and the engineering
  workstation and drops everything else, following the IEC 62443 idea of zones and conduits. With
  it in place, the attacker in A1-A3 could not reach the PLC at all.
- Zeek running live on a mirror (SPAN) port or a tap at the control network switch, instead of
  reading recordings afterwards.
- Zeek notices forwarded to a SIEM, where the security team would triage them.

## Reproduce it

Needs Docker with Compose. Run from this folder (`01-modbus-detection`).

```bash
# Re-run the detections on the published recordings (no lab needed)
# (writes to out/A2 so the published logs in evidence/ are left as they are)
mkdir -p out/A2
docker run --rm -v "$PWD/evidence/raw:/pcap:ro" -v "$PWD/lab/zeek:/zeek:ro" -v "$PWD/out/A2:/out" \
  -w /out zeek/zeek:latest zeek -C -r /pcap/A2.pcap /zeek/detect.zeek
grep -v '^#' out/A2/notice.log | cut -f 3,11,12

# Or rebuild the lab and record a new scenario (the pcap lands in evidence/raw/mytest.pcap)
docker compose -f lab/docker-compose.yml up -d
PCAP=mytest docker compose -f lab/docker-compose.yml --profile capture up -d capture
docker compose -f lab/docker-compose.yml exec attacker python mbcli.py 172.20.0.10 write 0 95
docker compose -f lab/docker-compose.yml --profile capture stop capture
docker compose -f lab/docker-compose.yml --profile capture down
```

`-C` makes Zeek ignore checksums, which are left unfinished on packets captured inside Docker.

## Evidence

| File | What it is |
|---|---|
| `evidence/raw/baseline.pcap`, `evidence/raw/A1.pcap` ... `A4.pcap` | One capture per scenario |
| `evidence/zeek/<scenario>/notice.log` | Alerts raised by `detect.zeek` (none for the baseline) |
| `evidence/zeek/<scenario>/modbus.log` | Every Modbus request and response Zeek decoded |
| `evidence/zeek/<scenario>/conn.log` | Connections |
| `lab/` | Compose file, Python Modbus code (`lab/app/`), Zeek script (`lab/zeek/detect.zeek`) |
