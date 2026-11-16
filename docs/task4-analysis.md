# Part 4: Running the Attack and Checking the Results

Every test below was really run against the live victim. All files these
results come from are kept in `pcap_files/` and `evidence/`. Files ending
in `_kali` are from the real Kali computer run, the main evidence for this
report. Files without that ending are from an earlier test setup, kept as
backup proof the tools behave the same either way.

## 1. Normal traffic first

Before attacking anything, I recorded what normal, honest traffic looks
like, captured on the real Kali computer's own Docker network.

```bash
python3 cups_detector.py --pcap pcap_files/baseline_normal_kali.pcap \
  --allowlist 10.13.37.20 --ipp-ports 631 \
  --out-json evidence/detector_baseline_kali.json --out-csv evidence/detector_baseline_kali.csv
```

Result: `packets_seen=1 browse_packets=1 ipp_requests=0 alerts=0`. Zero
false alarms. (An earlier, longer capture on the backup setup caught a
full exchange instead, 26 packets, same zero alarm result either way.)

## 2. The basic attack

```bash
sudo python3 cups_attack.py --target-ip 10.13.37.10 --attacker-ip 10.13.37.1 \
  --variant basic --ipp-port 16311 --wait-seconds 15 --iface br-xxxxxxxxxxxx \
  --pcap-out pcap_files/attack_variant1_basic_kali.pcap \
  --log-file evidence/attack_variant1_kali.log --summary-json evidence/attack_variant1_kali_summary.json
```

Result: the victim connected back in about forty milliseconds and asked
for the fake printer's details twice. cups browsed then fully set up a
print queue for it, seen both in the victim's own logs and in the live
CUPS web page, where the fake printer appeared in the list. This is a
real, working attack against the real, unpatched target.

One extra detail found while testing: cups browsed removes a printer
automatically if it stops hearing from it for about five minutes. Since
`cups_attack.py` sends one message by default, unlike the fake printer's
constant ten second loop, the fake printer disappears from the list a few
minutes later. This is not a mistake in the tool. It shows the attack only
causes a problem for a limited window of time unless repeated.

Detector result: 5 alerts, one unauthorized printer ad plus four
suspicious callbacks, see `evidence/detector_variant1_kali.json`.

## 3. Breaking the message on purpose

The assignment asked for at least three broken versions. I tested six
against the real victim.

| Test | What was broken | What happened |
|------|------------------|----------------|
| basic | nothing, the normal attack | Worked. Full fake printer added. |
| long text | info field made 4000 letters long | Worked anyway. No length check. |
| bad numbers | type and state fields were not numbers | Rejected. No callback. |
| odd symbols | line breaks and control codes added to a field | Worked anyway. Not cleaned up. |
| no quotes | required quote marks removed | Worked anyway. Parser is forgiving. |
| fake sender | sender address faked to match the real printer | Worked. Same as basic. |

All six were run and checked again on the real Kali computer, matching
the earlier setup exactly, result for result.

The fake sender test matters most. Even with a faked sender, the attack
still worked exactly like the normal one. This shows cups browsed decides
to trust a message based only on what the message itself claims, not on
who actually sent it. Faking the sender was not even needed to succeed.

## 4. Did the detector catch everything

| Test | Expected alert | Caught? |
|------|-----------------|---------|
| normal traffic | none | Yes, zero alerts |
| basic | printer ad plus callback | Yes, 5 alerts |
| long text | broken message plus callback | Yes, 5 alerts |
| bad numbers | broken message | Yes, after a fix, 1 alert |
| odd symbols | printer ad plus callback | Yes, 5 alerts, see note below |
| no quotes | broken message plus callback | Yes, 5 alerts |
| fake sender | callback only | Yes, 4 alerts, see note below |
| flood | too many ads | Yes, 39 alerts across 20 messages |

### A real bug I found and fixed

My first version of the detector completely missed the bad numbers test.
It required the message to start with something that looked like a
number, so a message starting with letters instead was ignored entirely,
instead of being flagged as a broken message. This was a real miss. I
fixed it by checking for the printer address format anywhere in the
message, since every version of this message always has one. After the
fix, this test is correctly caught, and normal traffic still gets zero
false alarms.

### Two honest limits, not hidden

- The odd symbols test is not flagged as broken, because the strange
  characters sit inside the quote marks, which my checker allows, since
  real printer names can include unusual characters too. A stricter check
  could catch this but might wrongly flag normal printers.
- The fake sender test only raises 4 alerts, not 5, because the faked
  address happens to match my trusted list, since it copies the real
  printer's own address. Neither my detector nor cups browsed itself can
  tell a faked address from a real one just by looking at it.

## 5. Summary

- Every kind of alert the assignment asked for was correctly raised at
  least once.
- Zero false alarms on normal traffic, before and after the fix.
- One real miss was found and fixed. Two honest limits remain and are
  written up above instead of hidden.
- The unpatched cups browsed software only rejected one out of four
  broken message tests. See [docs/task5-mitigation.md](task5-mitigation.md)
  for how the fix in Part 5 changes this.
