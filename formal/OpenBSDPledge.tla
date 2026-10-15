-------------------- MODULE OpenBSDPledge --------------------
EXTENDS TLC

VARIABLES phase, policyProtected, adapterAvailable, policySupported,
          networkPolicySupported, isolationActive, processExecuted

vars == <<phase, policyProtected, adapterAvailable, policySupported,
          networkPolicySupported, isolationActive, processExecuted>>
Phases == {"Ready", "Prepared", "Isolated", "Executed", "Failed"}

Init ==
    /\ phase = "Ready"
    /\ policyProtected \in BOOLEAN
    /\ adapterAvailable \in BOOLEAN
    /\ policySupported \in BOOLEAN
    /\ networkPolicySupported \in BOOLEAN
    /\ isolationActive = FALSE
    /\ processExecuted = FALSE

PrepareRequest ==
    /\ phase = "Ready"
    /\ phase' = "Prepared"
    /\ UNCHANGED <<policyProtected, adapterAvailable, policySupported,
                    networkPolicySupported,
                    isolationActive, processExecuted>>

RunExplicitFullAccess ==
    /\ phase = "Prepared"
    /\ ~policyProtected
    /\ phase' = "Executed"
    /\ processExecuted' = TRUE
    /\ UNCHANGED <<policyProtected, adapterAvailable, policySupported,
                    networkPolicySupported,
                    isolationActive>>

ApplyPledgeInPreExec ==
    /\ phase = "Prepared"
    /\ policyProtected
    /\ adapterAvailable
    /\ policySupported
    /\ networkPolicySupported
    /\ phase' = "Isolated"
    /\ isolationActive' = TRUE
    /\ UNCHANGED <<policyProtected, adapterAvailable, policySupported,
                    networkPolicySupported,
                    processExecuted>>

RejectUnavailableOrUnsupportedPolicy ==
    /\ phase = "Prepared"
    /\ policyProtected
    /\ (~adapterAvailable \/ ~policySupported \/ ~networkPolicySupported)
    /\ phase' = "Failed"
    /\ UNCHANGED <<policyProtected, adapterAvailable, policySupported,
                    networkPolicySupported,
                    isolationActive, processExecuted>>

ExecAfterPledge ==
    /\ phase = "Isolated"
    /\ phase' = "Executed"
    /\ processExecuted' = TRUE
    /\ UNCHANGED <<policyProtected, adapterAvailable, policySupported,
                    networkPolicySupported,
                    isolationActive>>

PledgeFailure ==
    /\ phase = "Isolated"
    /\ phase' = "Failed"
    /\ UNCHANGED <<policyProtected, adapterAvailable, policySupported,
                    networkPolicySupported,
                    isolationActive, processExecuted>>

Next == PrepareRequest \/ RunExplicitFullAccess
       \/ ApplyPledgeInPreExec \/ RejectUnavailableOrUnsupportedPolicy
       \/ ExecAfterPledge \/ PledgeFailure

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ policyProtected \in BOOLEAN
    /\ adapterAvailable \in BOOLEAN
    /\ policySupported \in BOOLEAN
    /\ networkPolicySupported \in BOOLEAN
    /\ isolationActive \in BOOLEAN
    /\ processExecuted \in BOOLEAN

ProtectedExecutionRequiresIsolation ==
    processExecuted => (~policyProtected \/ isolationActive)
FailureNeverExecutes == (phase = "Failed") => ~processExecuted
UnsupportedProtectedPolicyNeverExecutes ==
    processExecuted => (~policyProtected \/ (adapterAvailable /\ policySupported
                          /\ networkPolicySupported))

===============================================================