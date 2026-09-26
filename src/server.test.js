import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

function identity() {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const der = publicKey.export({ type: "spki", format: "der" });
    return { privateKey, signingPublicKey: der.toString("base64"),
        nodeId: createHash("sha256").update(der).digest("hex") };
}

async function client(port) {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/socket.io/?EIO=4&transport=websocket`);
    const events = [];
    let nextAck = 0;
    ws.addEventListener("message", ({ data }) => {
        if (data.startsWith("0")) ws.send("40");
        else if (data === "2") ws.send("3");
        else events.push(data);
    });
    ws.addEventListener("error", () => {});
    async function wait(prefix) {
        const deadline = Date.now() + 5000;
        while (Date.now() < deadline) {
            const index = events.findIndex(event => event.startsWith(prefix));
            if (index >= 0) return events.splice(index, 1)[0];
            await delay(10);
        }
        throw new Error(`Timed out waiting for ${prefix}; received ${events.join(",")}`);
    }
    await wait("40");
    return {
        close: () => ws.close(),
        event: async name => JSON.parse((await wait(`42["${name}"`)).slice(2))[1],
        async request(name, data) {
            const id = nextAck++;
            ws.send(`42${id}${JSON.stringify([name, data])}`);
            return JSON.parse((await wait(`43${id}[`)).slice(2 + String(id).length))[0];
        }
    };
}

async function authenticate(connection, id) {
    await connection.request("auth:init", { nodeId: id.nodeId, signingPublicKey: id.signingPublicKey });
    const challenge = await connection.event("auth:challenge");
    const payload = `PLEXUS_SERVER_AUTH_V1|${id.nodeId}|${challenge.challengeId}|${challenge.challenge}`;
    const result = await connection.request("auth:proof", {
        challengeId: challenge.challengeId,
        signature: sign("sha256", Buffer.from(payload), id.privateKey).toString("base64")
    });
    assert.equal(result.ok, true);
    await connection.event("auth:success");
}

test("real Socket.IO auth, offline queue, forgery rejection, and signed delivery", { timeout: 20000 }, async t => {
    const probe = createServer();
    await new Promise(resolve => probe.listen(0, "127.0.0.1", resolve));
    const port = probe.address().port;
    await new Promise(resolve => probe.close(resolve));
    const directory = await mkdtemp(join(tmpdir(), "plexus-server-test-"));
    const stateFile = join(directory, "state.json");
    const child = spawn(process.execPath, [new URL("./server.js", import.meta.url).pathname], {
        env: { ...process.env, PORT: String(port), REDIS_URL: "", PLEXUS_STATE_FILE: stateFile },
        stdio: ["ignore", "pipe", "pipe"]
    });
    let output = "";
    child.stdout.on("data", data => { output += data; });
    child.stderr.on("data", data => { output += data; });
    t.after(() => child.kill("SIGTERM"));
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
        try {
            const response = await fetch(`http://127.0.0.1:${port}/health`);
            if (response.ok) { ready = true; break; }
        } catch { /* server startup */ }
        await delay(50);
    }
    assert.ok(ready, output);
    const sender = identity();
    const receiver = identity();
    const a = await client(port);
    t.after(() => a.close());
    const now = Date.now();
    const inner = { version: 1, type: "encrypted_chat", messageId: randomUUID(),
        senderNodeId: sender.nodeId, recipientNodeId: receiver.nodeId, timestamp: now,
        nonce: Buffer.alloc(12).toString("base64"), ciphertext: Buffer.alloc(32).toString("base64") };
    const packet = { version: 1, type: "mesh_message", packetId: inner.messageId,
        sourceNodeId: sender.nodeId, destinationNodeId: receiver.nodeId,
        createdAt: now, expiresAt: now + 86400000, hopCount: 0,
        encryptedPayload: Buffer.from(JSON.stringify(inner)).toString("base64") };
    assert.equal((await a.request("internet:packet", packet)).ok, false);
    await authenticate(a, sender);
    assert.equal((await a.request("internet:packet", { ...packet, hopCount: 9 })).ok, false);
    assert.equal((await a.request("internet:packet", { ...packet, sourceNodeId: receiver.nodeId })).ok, false);
    assert.equal((await a.request("internet:packet", packet)).ok, true);
    assert.ok((await readFile(stateFile, "utf8")).includes(packet.packetId), "accepted packet is persisted");
    // The recipient was offline when the packet was accepted.
    const b = await client(port);
    t.after(() => b.close());
    await authenticate(b, receiver);
    assert.equal((await b.event("internet:packet")).packetId, packet.packetId);
    const antiPacket = { version: 1, type: "delivery_anti_packet", messageId: packet.packetId,
        sourceNodeId: sender.nodeId, recipientNodeId: receiver.nodeId,
        recipientSigningPublicKey: receiver.signingPublicKey, deliveredAt: now, expiresAt: now + 172800000 };
    const signed = `PLEXUS_DELIVERY_V1|${antiPacket.messageId}|${sender.nodeId}|${receiver.nodeId}|${now}|${antiPacket.expiresAt}`;
    antiPacket.signature = sign("sha256", Buffer.from(signed), receiver.privateKey).toString("base64");
    assert.equal((await a.request("internet:anti_packet", antiPacket)).ok, false, "only recipient uploads proof");
    assert.equal((await b.request("internet:anti_packet", { ...antiPacket, signature: "AAAA" })).ok, false);
    assert.equal((await b.request("internet:anti_packet", antiPacket)).ok, true);
    assert.equal((await a.event("internet:anti_packet")).messageId, packet.packetId);
    const conflict = { ...antiPacket, sourceNodeId: "c".repeat(64) };
    conflict.signature = sign("sha256", Buffer.from(
        `PLEXUS_DELIVERY_V1|${conflict.messageId}|${conflict.sourceNodeId}|${receiver.nodeId}|${now}|${conflict.expiresAt}`
    ), receiver.privateKey).toString("base64");
    assert.equal((await b.request("internet:anti_packet", conflict)).ok, false,
        "one signed ID cannot populate arbitrarily many source receipt queues");
    const repeated = await a.request("internet:packet", packet);
    assert.equal(repeated.deliveredAlready, true, "vaccine prevents resurrection");
});
