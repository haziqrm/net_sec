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

You play the attacker (10.0.0.9) on a LAN with a victim (10.0.0.5) and a gateway (10.0.0.1). Everything happens in memory: no packets are sent and your real network is never touched.

The commands mirror real Linux tools (`ip addr`, `arp -a`, `arp-scan -l`, `arpspoof -t`, `tcpdump`), so the skills transfer. Lines starting with `[sim]` report what the simulation did. `show-arp` and `explain` are marked `[teaching view]`, because a real attacker could not see that information. `wait` lets time pass, and the victim logs in to the gateway. Type `help` for the list, and leave with `exit`, Ctrl-D or Ctrl-C.

### The attack

Find the hosts, poison the victim's ARP entry for the gateway, then wait for the victim to log in:

```text
attacker# arp-scan -l
Interface: eth0, type: EN10MB, MAC: aa:aa:aa:aa:aa:09, IPv4: 10.0.0.9
Starting arp-scan with 256 hosts
10.0.0.1	aa:aa:aa:aa:aa:01	(Unknown)
10.0.0.5	aa:aa:aa:aa:aa:05	(Unknown)

Ending arp-scan: 256 hosts scanned. 2 responded
attacker# arpspoof -t 10.0.0.5 10.0.0.1
aa:aa:aa:aa:aa:09 aa:aa:aa:aa:aa:05 0806 42: arp reply 10.0.0.1 is-at aa:aa:aa:aa:aa:09
[sim] victim accepts reply: 10.0.0.1 is now at aa:aa:aa:aa:aa:09
attacker# show-arp victim
[teaching view] ARP table of victim (a real attacker cannot see this):
  ? (10.0.0.1) at aa:aa:aa:aa:aa:09 [ether] on eth0
attacker# wait
[sim] attacker intercepted 'POST /login user=alice' from victim meant for 10.0.0.1
attacker# tcpdump
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
IP 10.0.0.5 > 10.0.0.1: POST /login user=alice
```

### The defended replay

Start again with the defence on. The victim now has a static (locked) ARP entry for the gateway:

```bash
python -m playground.shell --defence
```

```text
attacker# show-arp victim
[teaching view] ARP table of victim (a real attacker cannot see this):
  ? (10.0.0.1) at aa:aa:aa:aa:aa:01 [ether] PERM on eth0
attacker# arpspoof -t 10.0.0.5 10.0.0.1
aa:aa:aa:aa:aa:09 aa:aa:aa:aa:aa:05 0806 42: arp reply 10.0.0.1 is-at aa:aa:aa:aa:aa:09
[sim] victim rejects reply: 10.0.0.1 is locked to aa:aa:aa:aa:aa:01, refusing aa:aa:aa:aa:aa:09
attacker# explain
[teaching view] Why: victim rejects reply: 10.0.0.1 is locked to aa:aa:aa:aa:aa:01, refusing aa:aa:aa:aa:aa:09
1. packet is an ARP reply (op=2): yes
2. 10.0.0.1 has a static (locked) entry: yes
3. claimed MAC aa:aa:aa:aa:aa:09 equals locked MAC aa:aa:aa:aa:aa:01: NO
4. decision: REJECT
attacker# wait
[sim] victim -> gateway: 'POST /login user=alice' delivered
attacker# tcpdump
listening on eth0, no packets captured yet
```

`explain` shows the checks behind the most recent event, so you can see exactly why the attack failed.
