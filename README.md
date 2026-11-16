# CUPS Printer Discovery Security Report

A class project. I built two tools in Python using Scapy to test and find
a real bug in CUPS printer software (CVE 2024 47176, CVE 2024 47076, and
CVE 2024 47175).

CUPS is the software many Linux computers use to find and talk to
printers. A helper program called cups browsed listens for messages that
announce new printers on the network, and it trusts these messages without
checking who sent them. This means anyone on the same network can pretend
to be a printer and trick the computer into connecting to them.

## What is in this project

- [`cups_attack.py`](cups_attack.py): sends the fake printer message using
  Scapy, in a few different forms, and checks if the victim connects back.
- [`cups_detector.py`](cups_detector.py): reads network traffic and raises
  an alert when it sees this trick happening. Works on a saved file or on
  live traffic.
- [`browse_proto.py`](browse_proto.py) and [`ipp_mini.py`](ipp_mini.py):
  small shared helper files used by both tools and by the fake honest
  printer below.
- [`lab/`](lab/): setup files for the test network. See
  [docs/task1-environment.md](docs/task1-environment.md).
- [`pcap_files/`](pcap_files/): saved network traffic from every test.
- [`evidence/`](evidence/): logs, result files, and screenshots.
- [`docs/`](docs/): written notes for each part of the assignment.
- `requirements.txt`: the one Python package needed (Scapy).

## Status: all five parts of the assignment are done

- Part 1, setup: [docs/task1-environment.md](docs/task1-environment.md)
- Parts 2 and 3, the tools: [cups_attack.py](cups_attack.py), [cups_detector.py](cups_detector.py)
- Part 4, testing: [docs/task4-analysis.md](docs/task4-analysis.md)
- Part 5, the fix: [docs/task5-mitigation.md](docs/task5-mitigation.md)

## How to run it

This is meant to be run on a real Kali Linux computer, which already has
Python and Scapy. The victim and fake printer run as Docker containers on
that same Kali computer.

```bash
git clone https://github.com/bemal4679/cups_attack_defense.git
cd cups_attack_defense/lab
docker-compose up -d victim legit_printer
cd ..

# find Kali's own address on the Docker network, needed below
ip -4 addr show | grep "10.13.37"

sudo python3 cups_attack.py --target-ip 10.13.37.10 --attacker-ip 10.13.37.1 \
  --variant basic --ipp-port 16311 --pcap-out pcap_files/demo.pcap -v
python3 cups_detector.py --pcap pcap_files/demo.pcap --allowlist 10.13.37.20 \
  --ipp-ports 631,16311 --out-json evidence/demo.json
```

`sudo` is needed for `cups_attack.py` since Scapy needs extra permission to
send and read raw network packets. `cups_detector.py --pcap` just reads a
saved file, so it does not need `sudo`.

See each tool's `--help` for every option, and
[docs/task4-analysis.md](docs/task4-analysis.md) for the exact commands
used for every file in `pcap_files/` and `evidence/`.

## The test setup

- Attacker: a real Kali Linux virtual machine, using Oracle VirtualBox.
- Victim: the official Vulhub test image for this exact bug, an old and
  unpatched copy of cups browsed, version 2.0.1, running in a Docker
  container on the Kali computer.
- Fake printer: a small program I wrote myself that acts like a normal,
  honest printer, so the detector has something normal to compare against.
  Also runs in a Docker container on the Kali computer.

## Staying safe and legal

Every test in this project only used computers on my own closed network,
nothing was reachable from outside my own machine, and no traffic was ever
sent to anyone else's computer or network.
