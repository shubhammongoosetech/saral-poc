package avss

// HARD SECURITY INVARIANT (Requirement R4):
// Secret reconstruction is NEVER reachable in any wallet or production key flow.
// Private signing keys are NEVER created, assembled, reconstructed, or persisted on any server, node,
// coordinator, database, or client device. Only public points (Y_i = x_i*G) and encrypted shares
// in local AES-256-GCM vaults exist.
