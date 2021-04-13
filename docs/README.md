# Handshakes studies

This is an incomplete set of handshake possibilities

## Case 1: A good handshake

```plantuml
@startuml
title Case 1: Good handshake

!pragma teoz true
skinparam sequenceMessageAlign center

actor "Initiator" as i
actor "Responder" as r

-> i: tun rx
i -> i: Stage 0: Prepare handshake
i -> r: stage 1 packet

r -> r: Stage 1: Stand up tunnel

r -> i: Stage 2 packet
i -> i: Stage 2: Stand up tunnel
@enduml
```

## Case 2: Stage 1 Race

Both sides try initiating at roughly the same time

Race avoidance is necessary, if we don't catch this at stage 1 then
both sides will have a tunnel with incorrect symmetric keys

```plantuml
@startuml
title Case 2: Stage 1 Race

!pragma teoz true
skinparam sequenceMessageAlign center

actor "Initiator 10.0.0.1" as i1
actor "Initiator 10.0.0.2" as i2

-> i1: tun rx
& i2 <- : tun rx
i1 -> i1: Stage 0: Prepare handshake
& i2 -> i2: Stage 0: Prepare handshake

i1 o<->o i2: Both send a stage 1

i1 -> i1: Stage 1: They won the race\nStand up tunnel\ndelete my pending attempt
& i2 ->x i2: Stage 1: I won the race\nIgnore this packet

i1 -> i2: Stage 2
i2 -> i2: Stage 2: Stand up tunnel
@enduml
```

## Case 3: Wrong responder

This affects nodes that have incorrect information about how to reach a given vpn ip

This avoidance behavior is specific to v1.4 and beyond.

### Case 3a: The correct host responds first

In this situation we are saved by the handshake already being complete however
the wrong responder believes they have a tunnel. If the wrong responder
attempts to send any messages our initiator will reply `recv_error` and eventually
the wrong responder will tear down it's broken tunnel.

```plantuml
@startuml
title Case 3a: Wrong responder loses the race

!pragma teoz true
skinparam sequenceMessageAlign center

actor "Wrong Responder" as rw
actor Initiator as i
actor "Good Responder" as rg

?-> i: tun rx
i -> i: Stage 0: Prepare handshake

i o-> rw: stage 1 packet
& i o-> rg: stage 1 packet

rg -> rg: Stage1: Stand up tunnel
& rw -> rw: Stage1: Stand up tunnel

rg -> i: Stage 2 packet
i -> i: Stand up tunnel

rw -> i: Stage 2
i ->x i: Rejected, handshake complete

@enduml
```

### Case 3b: The wrong responder wins the race

In this case the wrong responder wins the race, we detect this, block their address
and begin the handshake process over again. The good responders stage 2 packet
will be ignored.

```plantuml
@startuml
title Case 3b: Wrong responder wins the race

!pragma teoz true
skinparam sequenceMessageAlign center

actor "Wrong Responder" as rw
actor Initiator as i
actor "Good Responder" as rg

?-> i: tun rx
i -> i: Stage 0: Prepare handshake

i o-> rw: stage 1 packet
& i o-> rg: stage 1 packet

rg -> rg: Stage1: Stand up tunnel
& rw -> rw: Stage1: Stand up tunnel

rw -> i: Stage 2
i ->x i: Rejected, incorrect responder\nblock their address
i -> rw: close tunnel
rw -> rw: Tear down tunnel

rg -> i: Stage 2 packet
i ->x i: Rejected, tunnel does not exist

i -> i: Stage 0: Prepare handshake
i -> rg: stage 1 packet

rg -> rg: Stage 1: Stand up tunnel

rg -> i: Stage 2 packet
i -> i: Stage 2: Stand up tunnel
@enduml
```