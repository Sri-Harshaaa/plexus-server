export const MAX_MESH_HOPS = 8;
export const MAX_PACKET_BYTES = 32 * 1024;
const MESSAGE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const nodeId = /^[0-9a-f]{64}$/;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const base64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function validateMeshPacket(packet, now = Date.now()) {
    const invalid = reason => ({ valid: false, reason });
    if (!packet || Array.isArray(packet) || typeof packet !== "object" ||
        Buffer.byteLength(JSON.stringify(packet)) > MAX_PACKET_BYTES) {
        return invalid("INVALID_MESH_PACKET");
    }
    const { packetId, sourceNodeId, destinationNodeId, createdAt, expiresAt, hopCount, encryptedPayload } = packet;
    if (packet.version !== 1 || packet.type !== "mesh_message" ||
        typeof packetId !== "string" || !uuid.test(packetId) ||
        typeof sourceNodeId !== "string" || !nodeId.test(sourceNodeId) ||
        typeof destinationNodeId !== "string" || !nodeId.test(destinationNodeId) ||
        !Number.isSafeInteger(createdAt) || !Number.isSafeInteger(expiresAt) ||
        !Number.isSafeInteger(hopCount) || hopCount < 0 || hopCount > MAX_MESH_HOPS ||
        createdAt <= 0 || expiresAt <= createdAt || expiresAt - createdAt > MESSAGE_TTL_MS ||
        createdAt > now + MAX_FUTURE_SKEW_MS || expiresAt <= now ||
        typeof encryptedPayload !== "string" || !base64.test(encryptedPayload)) {
        return invalid("INVALID_MESH_PACKET_FIELDS");
    }
    try {
        const inner = JSON.parse(Buffer.from(encryptedPayload, "base64").toString("utf8"));
        if (inner.version !== 1 || inner.type !== "encrypted_chat" ||
            inner.messageId !== packetId || inner.senderNodeId !== sourceNodeId ||
            inner.recipientNodeId !== destinationNodeId || inner.timestamp !== createdAt ||
            typeof inner.nonce !== "string" || !base64.test(inner.nonce) ||
            Buffer.from(inner.nonce, "base64").length !== 12 ||
            typeof inner.ciphertext !== "string" || !base64.test(inner.ciphertext) ||
            inner.ciphertext.length > 24000 || Buffer.from(inner.ciphertext, "base64").length < 16) {
            return invalid("INNER_OUTER_MISMATCH");
        }
    } catch {
        return invalid("INVALID_ENCRYPTED_PAYLOAD");
    }
    return { valid: true };
}
