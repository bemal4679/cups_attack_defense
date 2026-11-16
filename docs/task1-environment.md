# Part 1: Setting Up the Test Network

## The setup

The attacker is a real Kali Linux virtual machine, using Oracle
VirtualBox. A virtual machine is a full computer running inside your real
computer, so testing stays safe. The victim and a fake printer both run as
Docker containers on that same Kali machine. A container is a small, boxed
up copy of a program kept separate from the rest of the computer.

All three parts talk to each other on one private network, address range
10.13.37.0/24, and nothing on this network can be reached from outside my
own computer.

| Part | Where it runs | Address |
|------|----------------|---------|
| Attacker | the real Kali Linux computer itself, Python and Scapy already installed | 10.13.37.1 |
| Victim | a container running the old, unpatched cups browsed software | 10.13.37.10 |
| Fake printer | a small program I wrote, acting like a normal, honest printer | 10.13.37.20 |

```bash
git clone https://github.com/bemal4679/cups_attack_defense.git
cd cups_attack_defense/lab
docker-compose up -d victim legit_printer
```

## Why a real Kali computer

This class expects Kali Linux as the attacker machine for every
assignment. Everything needed, Python, Scapy, and tcpdump, is already on
Kali by default, so no extra setup is needed there.

I first built and tested both tools in a simpler setup, where the attacker
was also just a container, so I could write and fix the code quickly. Once
the tools worked, I ran every test again from scratch on the real Kali
computer. Both runs gave the same results. Files from the real Kali run
have names ending in `_kali`, and this report mainly talks about those.
Files from the earlier setup are kept too, as backup proof.

## Why this bug matters

- CVE 2024 47176: cups browsed listens for an old style of network message
  that announces a printer, and trusts it completely without checking who
  sent it.
- CVE 2024 47076 and CVE 2024 47175: once the victim connects to a fake
  printer, the fake printer can send back bad data that gets used to build
  a print driver file without being checked first. A hidden command can be
  smuggled inside.
- Together, this chain is sometimes called CVE 2024 47177, even though
  that name was later removed from the official list. An attacker on the
  same network can eventually get the victim to run a command of their
  choosing the next time someone prints.

I checked the exact wording of this fake printer message against Vulhub's
own instructions for this target, a small example program called evil ipp
server that Vulhub points to, and a security write up by a researcher
known as evilsocket. The message looks like this:

```
type state printer_address "location" "info"
example:  0 3 ipp://10.13.37.1:16311/printers/EVIL-PRINTER "Attacker Controlled" "Totally Legit Printer"
```

My `cups_attack.py` does not copy that example program's code. I wrote my
own version with Scapy, as the assignment asked. It also has an optional
setting, turned off by default, that can repeat the full public example
including the hidden command trick. This is not needed for the
assignment, since we only need to show the discovery bug itself.

## The fake printer

`lab/legit_printer/legit_ipp_printer.py` is not one of the graded tools.
It is test setup only, standing in for a real printer on the network, so
there is something normal and honest for the detector to not alarm on. It
does two things:

1. Tells the victim about itself every ten seconds, using a plain network
   message, not Scapy, since this is meant to look like normal traffic.
2. Answers printer detail requests with normal, honest information.

## Recording normal traffic

With the test network running, normal traffic is recorded directly on the
Kali computer's own Docker network. Since Kali is the computer running
Docker, it can see all the traffic crossing that network without any extra
setup.

```bash
ip -4 addr show | grep 10.13.37
sudo timeout 15 tcpdump -i br-xxxxxxxxxxxx -w pcap_files/baseline_normal_kali.pcap \
  "udp port 631 or tcp port 631"
```

See [docs/task4-analysis.md](task4-analysis.md) for what this normal
traffic looks like, and how it compares to the attack.
