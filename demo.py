"""Runs a level with and without the defence and prints the events."""

from __future__ import annotations

from playground.engine.actions import ForgeArpReply, SendTraffic, SetStaticEntry
from playground.engine.engine import run
from playground.engine.goals import check_goal
from playground.engine.scenarios import GATEWAY_IP, GATEWAY_MAC, simple_lan

ATTACK = [
    ForgeArpReply(sender="attacker", target="victim", claimed_ip=GATEWAY_IP),
    SendTraffic(sender="victim", dest_ip=GATEWAY_IP, payload="password=hunter2"),
]
DEFENCE = [SetStaticEntry(host="victim", ip=GATEWAY_IP, mac=GATEWAY_MAC)]
GOAL = {"type": "traffic_captured", "attacker": "attacker", "src": "victim"}


def play(title: str, actions: list) -> None:
    """Run ``actions`` on a fresh LAN and print events, traces and the goal result."""
    print(f"=== {title} ===")
    net, events = run(simple_lan(), actions)
    for event in events:
        print(f"[{event.kind}] {event.text}")
        for step in event.trace:
            print(f"    - {step.check}: {step.result}")
    print("GOAL REACHED" if check_goal(net, GOAL) else "GOAL NOT REACHED")
    print()


def main() -> None:
    play("Defence off", ATTACK)
    play("Defence on (static ARP entry for the gateway)", DEFENCE + ATTACK)


if __name__ == "__main__":
    main()
