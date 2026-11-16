# Project status

## Part 1, setup: done

Victim and fake printer run as Docker containers on a real Kali Linux
computer, which also runs the attack tool itself, all on one closed test
network. See [task1-environment.md](task1-environment.md).

## Parts 2 and 3, the tools: done

`cups_attack.py` sends the fake printer message in four different ways,
and watches for the victim connecting back. `cups_detector.py` reads a
saved file or live traffic and raises four kinds of alerts.

## Part 4, testing: done

Normal traffic plus six attack tests were all run against the real
victim, checked by the detector. One real miss in the detector was found
and fixed, and two honest limits are written up instead of hidden. See
[task4-analysis.md](task4-analysis.md).

## Part 5, the fix: done

A trusted address list was added and tested, shown to fully stop the
attack while leaving the real printer working. Other possible fixes are
discussed too. See [task5-mitigation.md](task5-mitigation.md).

## The report

A separate written report covers the setup, the tools, the testing,
the fix, and how this project stayed safe and legal.
