-- HashGuard-ID Atomic Compare-And-Swap (CAS) & Replay Defense Engine
-- Standards   : NIST SP 800-63B (§5.1.3.2), RFC 2289, Redis Cluster Specification
-- Complexity  : Time O(1), Space O(1)
-- Invariants  : Zero TOCTOU, Monotonic Sequence Descent, Cluster Hash Slot Determinism

-- Explicit Redis Cluster Key Vector: MUST evaluate to identical CRC16 Hash Slot
local anchor_key         = KEYS[1] -- {user:<id>}:anchor
local step_key           = KEYS[2] -- {user:<id>}:step
local nonce_key          = KEYS[3] -- {user:<id>}:nonce:<val>
local pending_anchor_key = KEYS[4] -- {user:<id>}:pending_anchor
local pending_step_key   = KEYS[5] -- {user:<id>}:pending_step

local claimed_step   = tonumber(ARGV[1])
local claimed_token  = ARGV[2]
local nonce          = ARGV[3]
local nonce_ttl      = tonumber(ARGV[4])
local max_lookahead  = tonumber(ARGV[5])
local next_anchor    = ARGV[6]
local next_steps     = tonumber(ARGV[7])

-- 1. Anti-Replay Defense: O(1) Nonce Verification
if redis.call("EXISTS", nonce_key) == 1 then
    return redis.error_reply("ERR_NONCE_REPLAY")
end

-- 2. State Existence & Monotonic Descent Invariant
local current_step = tonumber(redis.call("GET", step_key))
if not current_step then
    return redis.error_reply("ERR_USER_NOT_FOUND")
end

if claimed_step >= current_step then
    return redis.error_reply("ERR_SEQUENCE_VIOLATION")
end

-- 3. Bounded Mobile Packet-Loss Desynchronization Window
local delta = current_step - claimed_step
if delta > max_lookahead then
    return redis.error_reply("ERR_LOOKAHEAD_EXCEEDED")
end

-- 4. O(1) Hardware-Offloaded Candidate Anchor Matching
-- Candidate array mapping: ARGV[7 + delta] == H^delta(claimed_token)
local expected_anchor = ARGV[7 + delta]
local current_anchor = redis.call("GET", anchor_key)

if expected_anchor ~= current_anchor then
    return redis.error_reply("ERR_PREIMAGE_MISMATCH")
end

-- 5. Atomic State Commit & Nonce Invalidation
redis.call("SET", anchor_key, claimed_token)
redis.call("SET", step_key, claimed_step)
redis.call("SET", nonce_key, "1", "EX", nonce_ttl)

-- 6. Silent Re-anchoring Ingestion (Piggybacked Successor Chain Anchor)
if next_anchor and #next_anchor == 64 and next_steps and next_steps > 0 then
    redis.call("SET", pending_anchor_key, next_anchor)
    redis.call("SET", pending_step_key, next_steps)
end

-- 7. Boundary Transition: Atomic Succession at Chain Exhaustion (k = 0)
if claimed_step == 0 then
    local p_anchor = redis.call("GET", pending_anchor_key)
    local p_steps = tonumber(redis.call("GET", pending_step_key))
    if p_anchor and p_steps and p_steps > 0 then
        redis.call("SET", anchor_key, p_anchor)
        redis.call("SET", step_key, p_steps)
        redis.call("DEL", pending_anchor_key)
        redis.call("DEL", pending_step_key)
        return {p_steps, p_anchor, "ROLLED_OVER_ATOMIC"}
    end
end

return {claimed_step, claimed_token, "COMMITTED_ATOMIC"}