# ICS/OT security labs

Hands-on labs in industrial control system (ICS) and operational technology (OT) network security:
a simulated control network, its traffic recorded, and detections written and tested against it.
Each lab is a folder with its own write-up, code and evidence. These are simulated labs, not plant
experience.

| Lab | What it shows |
|---|---|
| [01 - Modbus detection](01-modbus-detection/) | A PLC, HMI, engineering workstation and attacker in Docker; three Zeek detections for Modbus/TCP (unauthorized writes, unsafe setpoints, device fingerprinting) tested against a baseline and four scenarios |

Built by Matt Mumbach (CISSP, GCIA, GPEN, AWS CCP). Cloud security work is in
[aws-security-portfolio](https://github.com/mattmumbach/aws-security-portfolio).

Evidence files are checked by `scripts/redact-audit.sh` before every commit
(`git config core.hooksPath .githooks`).
