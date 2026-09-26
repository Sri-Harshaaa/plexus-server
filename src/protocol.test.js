import test from "node:test";
import assert from "node:assert/strict";
import { validateMeshPacket, MAX_MESH_HOPS } from "./protocol.js";

const now = 1_800_000_000_000;
function packet() {
    const inner = { version: 1, type: "encrypted_chat",
        messageId: "11111111-2222-4333-8444-555555555555",
        senderNodeId: "a".repeat(64), recipientNodeId: "b".repeat(64),
        timestamp: now, nonce: Buffer.alloc(12).toString("base64"),
        ciphertext: Buffer.alloc(32).toString("base64") };
    return { version: 1, type: "mesh_message", packetId: inner.messageId,
        sourceNodeId: inner.senderNodeId, destinationNodeId: inner.recipientNodeId,
        createdAt: now, expiresAt: now + 86400000, hopCount: 0,
        encryptedPayload: Buffer.from(JSON.stringify(inner)).toString("base64") };
}
test("origin and final allowed hop are valid", () => {
    assert.equal(validateMeshPacket(packet(), now).valid, true);
    assert.equal(validateMeshPacket({ ...packet(), hopCount: MAX_MESH_HOPS }, now).valid, true);
});
test("negative, excessive, fractional and coerced hops are rejected", () => {
    for (const hopCount of [-1, 9, 1.5, "1", Number.MAX_SAFE_INTEGER]) {
        assert.equal(validateMeshPacket({ ...packet(), hopCount }, now).valid, false);
    }
});
test("expiry boundary, extended TTL and future timestamp are rejected", () => {
    assert.equal(validateMeshPacket(packet(), now + 86400000).valid, false);
    assert.equal(validateMeshPacket({ ...packet(), expiresAt: now + 86400001 }, now).valid, false);
    assert.equal(validateMeshPacket(packet(), now - 300001).valid, false);
});
test("forged outer source and destination cannot be routed", () => {
    for (const field of ["sourceNodeId", "destinationNodeId"]) {
        assert.equal(validateMeshPacket({ ...packet(), [field]: "c".repeat(64) }, now).valid, false);
    }
});
test("malformed, oversized and unsupported packets are rejected", () => {
    for (const value of [null, [], {}, { ...packet(), version: 2 },
        { ...packet(), encryptedPayload: "!" },
        { ...packet(), padding: "x".repeat(32768) }]) {
        assert.equal(validateMeshPacket(value, now).valid, false);
    }
});
