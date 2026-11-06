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

You play the attacker on a LAN with a victim and a gateway. Everything happens in memory: no packets are sent and your real network is never touched. Lines starting with `[sim]` report what the simulation did. `show-arp` and `explain` start with `[teaching view]`, because a real attacker could not see that information. `wait` lets time pass, and the victim logs in to the gateway. Type `help` for the commands and `exit` to leave.

### The attack

Find your own IP and MAC, find the other hosts, then tell the victim (10.0.0.5) that the gateway's IP (10.0.0.1) is at your MAC:

```text
attacker# ip addr
eth0  ip 10.0.0.9  mac aa:aa:aa:aa:aa:09
attacker# arp-scan -l
10.0.0.1  aa:aa:aa:aa:aa:01
10.0.0.5  aa:aa:aa:aa:aa:05
2 hosts found
attacker# arpspoof -t 10.0.0.5 --mac aa:aa:aa:aa:aa:09 10.0.0.1
sent: 10.0.0.1 is at aa:aa:aa:aa:aa:09
[sim] victim accepts reply: 10.0.0.1 is now at aa:aa:aa:aa:aa:09
attacker# show-arp victim
[teaching view]
10.0.0.1 -> aa:aa:aa:aa:aa:09
attacker# wait
[sim] attacker intercepted 'POST /login user=alice' from victim meant for 10.0.0.1
attacker# tcpdump
10.0.0.5 -> 10.0.0.1: POST /login user=alice
```

### The defended replay

Start again with the defence on. The victim now has a locked (static) ARP entry for the gateway:

```bash
python -m playground.shell --defence
```

```text
attacker# show-arp victim
[teaching view]
10.0.0.1 -> aa:aa:aa:aa:aa:01 (locked)
attacker# arpspoof -t 10.0.0.5 --mac aa:aa:aa:aa:aa:09 10.0.0.1
sent: 10.0.0.1 is at aa:aa:aa:aa:aa:09
[sim] victim rejects reply: 10.0.0.1 is locked to aa:aa:aa:aa:aa:01, refusing aa:aa:aa:aa:aa:09
attacker# explain
[teaching view]
victim rejects reply: 10.0.0.1 is locked to aa:aa:aa:aa:aa:01, refusing aa:aa:aa:aa:aa:09
1. packet is an ARP reply (op=2): yes
2. 10.0.0.1 has a static (locked) entry: yes
3. claimed MAC aa:aa:aa:aa:aa:09 equals locked MAC aa:aa:aa:aa:aa:01: no
4. decision: REJECT
attacker# wait
[sim] victim -> gateway: 'POST /login user=alice' delivered
attacker# tcpdump
no packets captured
```

`explain` shows the checks behind the most recent event, so run it straight after `arpspoof` to see why the attack failed.
