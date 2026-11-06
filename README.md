# security-playground

A sandboxed network-security playground where students experiment with attacks and defences on a simulated network. The engine models network state as immutable data, applies student actions to produce new states and events, and checks level goals against the result, starting with ARP spoofing and its defences.

## How to run

### Setup

### Run the demo

### Run the tests

## Try it

Start the simulated shell from the project folder:

```bash
python -m playground.shell
```

You play the attacker on a LAN with a victim (10.0.0.5), a gateway (10.0.0.1) and yourself (10.0.0.9). Everything happens in memory: no packets are sent and your real network is never touched. Type `help` to list the commands. `wait` lets time pass, and the victim logs in to the gateway. Leave with `exit`, Ctrl-D or Ctrl-C.

### The attack

Poison the victim's ARP entry for the gateway, then wait for the victim to log in:

```text
attacker$ arp -a victim
ARP table of victim:
  10.0.0.1 at aa:aa:aa:aa:aa:01
attacker$ arpspoof victim 10.0.0.1
[sent] attacker sends ARP reply to victim: 10.0.0.1 is at aa:aa:aa:aa:aa:09
[accepted] victim accepts reply: 10.0.0.1 is now at aa:aa:aa:aa:aa:09
attacker$ arp -a victim
ARP table of victim:
  10.0.0.1 at aa:aa:aa:aa:aa:09
attacker$ wait
[intercepted] attacker intercepted 'POST /login user=alice' from victim meant for 10.0.0.1
attacker$ captured
from victim to 10.0.0.1: POST /login user=alice
```

### The defended replay

Start again with the defence on. The victim now has a static (locked) ARP entry for the gateway:

```bash
python -m playground.shell --defence
```

```text
attacker$ arp -a victim
ARP table of victim:
  10.0.0.1 at aa:aa:aa:aa:aa:01 (static)
attacker$ arpspoof victim 10.0.0.1
[sent] attacker sends ARP reply to victim: 10.0.0.1 is at aa:aa:aa:aa:aa:09
[rejected] victim rejects reply: 10.0.0.1 is locked to aa:aa:aa:aa:aa:01, refusing aa:aa:aa:aa:aa:09
attacker$ explain
Why: victim rejects reply: 10.0.0.1 is locked to aa:aa:aa:aa:aa:01, refusing aa:aa:aa:aa:aa:09
1. packet is an ARP reply (op=2): yes
2. 10.0.0.1 has a static (locked) entry: yes
3. claimed MAC aa:aa:aa:aa:aa:09 equals locked MAC aa:aa:aa:aa:aa:01: no
4. decision: REJECT
attacker$ wait
[delivered] victim -> gateway: 'POST /login user=alice' delivered
attacker$ captured
nothing captured yet
```

`explain` shows the checks behind the most recent event, so you can see exactly why the attack failed.
