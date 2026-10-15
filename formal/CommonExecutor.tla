-------------------- MODULE CommonExecutor --------------------
EXTENDS TLC

VARIABLES phase, sandboxSelected, processExecuted

vars == <<phase, sandboxSelected, processExecuted>>
Phases == {"Ready", "Prepared", "Protected", "Executed", "Rejected"}
SandboxTypes == {"None", "VerifiedAdapter"}

Init ==
    /\ phase = "Ready"
    /\ sandboxSelected \in SandboxTypes
    /\ processExecuted = FALSE

PrepareRequest ==
    /\ phase = "Ready"
    /\ phase' = "Prepared"
    /\ UNCHANGED <<sandboxSelected, processExecuted>>

RejectUnprotectedRequest ==
    /\ phase = "Prepared"
    /\ sandboxSelected = "None"
    /\ phase' = "Rejected"
    /\ UNCHANGED <<sandboxSelected, processExecuted>>

SelectVerifiedAdapter ==
    /\ phase = "Prepared"
    /\ sandboxSelected = "VerifiedAdapter"
    /\ phase' = "Protected"
    /\ UNCHANGED <<sandboxSelected, processExecuted>>

SpawnProtectedRequest ==
    /\ phase = "Protected"
    /\ phase' = "Executed"
    /\ processExecuted' = TRUE
    /\ UNCHANGED sandboxSelected

AdapterFailure ==
    /\ phase = "Protected"
    /\ phase' = "Rejected"
    /\ UNCHANGED <<sandboxSelected, processExecuted>>

Next == PrepareRequest \/ RejectUnprotectedRequest \/ SelectVerifiedAdapter
       \/ SpawnProtectedRequest \/ AdapterFailure

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ sandboxSelected \in SandboxTypes
    /\ processExecuted \in BOOLEAN

NoUnprotectedSpawn == processExecuted => sandboxSelected = "VerifiedAdapter"
RejectedNeverExecutes == (phase = "Rejected") => ~processExecuted

===============================================================