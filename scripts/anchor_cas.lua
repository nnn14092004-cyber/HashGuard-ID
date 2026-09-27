-- HashGuard-ID Atomic Compare-And-Swap (CAS) & Replay Defense Engine
-- Standards: NIST SP 800-63B, RFC 2289
-- Complexity: Time O(1), Space O(1)

-- KEYS[1]: User State Key ("hashguard:anchor:<account_id>")
-- KEYS[2]: Nonce Key      ("hashguard:nonce:<nonce_value>")

-- ARGV[1]: Expected Current Anchor (Hex-encoded 32 bytes: H(T_k))
-- ARGV[2]: New Anchor Token (Hex-encoded 32 bytes: T_k)
-- ARGV[3]: Claimed Step Index (Integer: k)
-- ARGV[4]: Nonce Value (String)
-- ARGV[5]: Nonce TTL in Seconds (Integer: e.g., 300)

-- 1. Anti-Replay Verification (O(1))
if redis.call('EXISTS', KEYS[2]) == 1 then
    return redis.error_reply("ERR_REPLAY_ATTACK_DETECTED")
end

-- 2. State Existence & Integrity Check
local current_anchor = redis.call('HGET', KEYS[1], 'anchor')
local current_step = tonumber(redis.call('HGET', KEYS[1], 'step'))

if not current_anchor or not current_step then
    return redis.error_reply("ERR_ANCHOR_UNINITIALIZED")
end

-- 3. Monotonic Decreasing Enclosure
local claimed_step = tonumber(ARGV[3])
if claimed_step >= current_step then
    return redis.error_reply("ERR_SEQUENCE_VIOLATION")
end

-- 4. Cryptographic Anchor Invariant Check (H(T_k) == current_anchor)
if current_anchor ~= ARGV[1] then
    return redis.error_reply("ERR_PREIMAGE_MISMATCH")
end

-- 5. Atomic State Transition & Nonce Invalidation
redis.call('HSET', KEYS[1], 'anchor', ARGV[2], 'step', claimed_step)
redis.call('SETEX', KEYS[2], tonumber(ARGV[5]), ARGV[4])

-- Return remaining chain depth
return {1, claimed_step}