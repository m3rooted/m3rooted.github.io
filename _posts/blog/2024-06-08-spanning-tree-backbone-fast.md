---
layout: post
title: "Spanning-Tree Backbone Fast"
subtitle: "Indirect Link Failure Recovery"
category: blog
tags: networking switching stp cisco
titles_from_headings: false
---

Backbone Fast is used to recover from an indirect link failure. What does that mean? This post walks through a concrete example and the debug output that shows how spanning-tree reacts.

<!--more-->

* this unordered seed list will be replaced by the toc
{:toc}

## Scenario Overview

![Backbone Fast topology diagram](/assets/img/2024-06-08/spanning.png)

SW1 is the root bridge. The Fa0/16 interface on SW3 is blocked. Suddenly the link between SW1 and SW2 fails. From SW3's perspective, this is an indirect link failure.

When the SW1-SW2 link goes down, this is what happens:

1. SW2 detects the failure immediately because it is a directly connected link. Since it no longer receives BPDUs from the root, it assumes it is the new root bridge and sends BPDUs toward SW3 claiming to be the root.
2. SW3 receives these BPDUs from SW2 but recognizes they are inferior compared to the BPDU currently stored on Fa0/16, and it ignores the new BPDU. An inferior BPDU implies the neighbor has lost its connection to the root bridge.
3. After 20 seconds (default max age), the max age timer expires for the old BPDU on Fa0/16 of SW3. The interface transitions from blocking to listening and starts sending BPDUs toward SW2.
4. SW2 receives these BPDUs from SW3 and discovers it is not the root bridge, so it stops sending BPDUs toward SW3.
5. The Fa0/16 interface on SW3 continues from listening (15 seconds) to learning (15 seconds), then enters forwarding.

Connectivity is restored, but it took 20 seconds for max age to expire, 15 seconds for listening, and 15 seconds for learning. That is 50 seconds of downtime in total.

## Debug Output (Without Backbone Fast)

Enable debugging on SW2 and SW3:

```text
SW2#debug spanning-tree events
Spanning Tree event debugging is on

SW3#debug spanning-tree events
Spanning Tree event debugging is on
```

Shut down the SW1 Fa0/14 interface to simulate the indirect link failure:

```text
SW1(config)#interface fa0/14
SW1(config-if)#shutdown
```

SW2 now believes it is the root bridge:

```text
SW2# STP: VLAN0001 we are the spanning tree root
```

SW3 receives the inferior BPDU from SW2:

```text
SW3# STP: VLAN0001 heard root 8193-0019.569d.5700 on Fa0/16
```

After max age expires, SW3 transitions Fa0/16:

```text
SW3# STP: VLAN0001 Fa0/16 -> listening
SW3# STP: VLAN0001 Fa0/16 -> learning
SW3# STP: VLAN0001 Fa0/16 -> forwarding
```

SW2 eventually learns the real root through SW3:

```text
SW2# STP: VLAN0001 heard root 4097-0011.bb0b.3600 on Fa0/16
SW2# STP: VLAN0001 new root is 4097, 0011.bb0b.3600 on port Fa0/16, cost 38
```

Without Backbone Fast, spanning-tree discards the inferior BPDUs received on SW3 Fa0/16 and waits for the max age timer to expire.

## Enable Backbone Fast

Bring the link back up first:

```text
SW1(config)#interface fa0/14
SW1(config-if)#no shutdown
```

Enable Backbone Fast globally on all switches:

```text
SW1(config)#spanning-tree backbonefast
SW2(config)#spanning-tree backbonefast
SW3(config)#spanning-tree backbonefast
```

Enable debug output for Backbone Fast:

```text
SW1#debug spanning-tree backbonefast detail
Spanning Tree backbonefast detail debugging is on

SW2#debug spanning-tree events
Spanning Tree event debugging is on

SW3#debug spanning-tree backbonefast detail
Spanning Tree backbonefast detail debugging is on
```

## Debug Output (With Backbone Fast)

Simulate the indirect link failure again:

```text
SW1(config)#interface fa0/14
SW1(config-if)#shutdown
```

SW2 again believes it is the root bridge:

```text
SW2# STP: VLAN0001 we are the spanning tree root
```

SW1 receives a Root Link Query (RLQ) from SW3 and responds:

```text
SW1# STP FAST: VLAN0001 FastEthernet0/17: sending requested RLQ response PDU
```

SW3 receives the RLQ response on Fa0/14:

```text
SW3# STP FAST: received RLQ response PDU was expected on VLAN0001
FastEthernet0/14 - resp root id 4097-0011.bb0b.3600
```

SW3 then processes the inferior BPDU on Fa0/16 and moves that port to designated:

```text
SW3# STP FAST: received_rlq_bpdu on VLAN0001 FastEthernet0/16 - making FastEthernet0/16 a designated port
```

Because SW3 received a response from the root bridge on Fa0/14, it can skip the max age timer on Fa0/16. The interface transitions to listening and learning immediately, saving 20 seconds.

## Final Configurations

SW1:

```text
hostname SW1
!
spanning-tree backbonefast
!
end
```

SW2:

```text
hostname SW2
!
spanning-tree backbonefast
!
end
```

SW3:

```text
hostname SW3
!
spanning-tree backbonefast
!
end
```
