# Part 5: Fixing the Problem

## The fix: a trusted address list

cups browsed has a settings file that supports a trusted address list,
also called an allowlist. Everything not on the list gets blocked. This
matches the assignment's idea of only trusting known printer addresses,
and works better than simply blocking a network port, since a trusted
printer still works normally. I added these lines to the victim's
settings file:

```
BrowseOrder Deny,Allow
BrowseDeny All
BrowseAllow 10.13.37.20
```

I then restarted cups browsed so it would read the new settings.

## Before and after

Tested twice, once on the earlier backup setup and once on the real Kali
computer. The results below are from the real Kali run.

| Check | Before the fix | After the fix |
|-------|-----------------|----------------|
| victim's own log | nothing unusual | says the message was not allowed |
| victim connects back | yes, within milliseconds | no, never happens |
| detector alerts | 5 alerts total | 1 alert, message still seen but ignored |
| real printer still works | yes | yes, still works fine |

I chose not to use a CUPS web page screenshot as proof for this part. The
printer list page looks the same whether the fake printer was actually
blocked, or simply has not sent a new message recently, as explained in
Part 4. A screenshot like that would be confusing on its own. The clear
log message and the tool's own result are much better, unmistakable
proof.

In short, this fix fully stops the attack from working, without breaking
the real printer, and without needing to change any firewall settings.

## Other fixes I considered

- Blocking the network port: also works, and stops the message even
  earlier, but the test computer did not have a firewall tool installed,
  and it would need to be kept in sync with the trusted address list by
  hand.
- Turning off cups browsed completely: removes the problem entirely, but
  also removes the ability to find printers automatically.
- Updating the software: the real fix. Newer versions of CUPS do not
  trust these messages the same way. This old version was used on purpose
  for this class to study the bug safely.
- Splitting the network: keeping printers on their own separate part of
  the network is a good extra layer of safety, used together with the
  other fixes, not instead of them.
