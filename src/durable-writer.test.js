import test from "node:test";
import assert from "node:assert/strict";
import { createDurableWriter } from "./durable-writer.js";
const tick = () => new Promise(resolve => setImmediate(resolve));

test("10,000 mutations coalesce into two snapshots with separate durability barriers", async () => {
    let value = 0, snapshots = 0;
    const writes = [], releases = [];
    const writer = createDurableWriter(() => { snapshots++; return { value }; }, serialized => {
        writes.push(serialized);
        return new Promise(resolve => releases.push(resolve));
    });
    const first = writer.persist();
    await tick();
    const callers = [];
    for (value = 1; value <= 10000; value++) callers.push(writer.persist());
    assert.equal(snapshots, 1, "pending mutations must not serialize");
    assert.equal(new Set(callers).size, 1, "one pending batch promise, not a writer promise chain");
    let secondDurable = false;
    callers[0].then(() => { secondDurable = true; });
    releases.shift()();
    await first;
    await tick();
    assert.equal(secondDurable, false);
    assert.equal(writes.length, 2);
    assert.equal(JSON.parse(writes[1]).value, 10001);
    releases.shift()();
    await Promise.all(callers);
    await writer.flush();
    const stats = writer.diagnostics();
    assert.equal(stats.writes, 2);
    assert.equal(stats.coalescedMutations, 9999);
    assert.equal(stats.lastSnapshotBytes, Buffer.byteLength(writes[1]));
    assert.equal(stats.persistedGeneration, stats.generation);
});

test("failure rejects barrier and later barrier retries dirty state", async () => {
    let fail = true;
    const writer = createDurableWriter(() => ({ value: 1 }), async () => {
        if (fail) throw new Error("disk unavailable");
    });
    await assert.rejects(writer.persist(), /disk unavailable/);
    assert.equal(writer.diagnostics().persistedGeneration, 0);
    fail = false;
    await writer.barrier();
    await writer.flush();
    assert.equal(writer.diagnostics().failedWrites, 1);
    assert.equal(writer.diagnostics().writes, 1);
});

test("flush waits for mutations arriving during an active write", async () => {
    let release;
    let count = 0;
    const writer = createDurableWriter(() => ({ count }), async () => {
        if (++count === 1) await new Promise(resolve => { release = resolve; });
    });
    const initial = writer.persist();
    await tick();
    const final = writer.persist();
    let flushed = false;
    const flush = writer.flush().then(() => { flushed = true; });
    await tick();
    assert.equal(flushed, false);
    release();
    await Promise.all([initial, final, flush]);
    assert.equal(count, 2);
});

test("continuous mutations are paced while their acknowledgements wait for disk", async () => {
    let count = 0;
    const writer = createDurableWriter(() => ({ count }), async () => { count++; }, 80);
    await writer.persist();
    const promises = Array.from({ length: 100 }, () => writer.persist());
    await tick();
    assert.equal(count, 1);
    await Promise.all(promises);
    assert.equal(count, 2);
});
