// At most one serialized snapshot and one pending batch. A batch promise is a
// durability barrier, not merely an acknowledgement that work was scheduled.
export function createDurableWriter(snapshot, write, minWriteIntervalMs = 0) {
    let generation = 0, persistedGeneration = 0, active = null, pending = null;
    let lastStarted = -Infinity, timer = null;
    const stats = { writes: 0, failedWrites: 0, coalescedMutations: 0, lastSnapshotBytes: 0, lastWriteMs: 0 };
    function request() {
        generation++;
        if (pending) { stats.coalescedMutations++; return pending.promise; }
        let resolve, reject;
        const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
        pending = { promise, resolve, reject };
        schedule();
        return promise;
    }
    function schedule() {
        if (active || !pending || timer) return;
        const wait = Math.max(0, minWriteIntervalMs - (performance.now() - lastStarted));
        if (wait > 0) timer = setTimeout(() => { timer = null; pump(); }, wait);
        else queueMicrotask(pump);
    }
    async function pump() {
        if (active || !pending) return;
        const batch = pending;
        pending = null;
        active = batch;
        const captured = generation;
        const started = performance.now();
        lastStarted = started;
        try {
            const serialized = JSON.stringify(snapshot());
            stats.lastSnapshotBytes = Buffer.byteLength(serialized);
            await write(serialized);
            stats.writes++;
            persistedGeneration = captured;
            batch.resolve();
        } catch (error) {
            stats.failedWrites++;
            batch.reject(error);
        } finally {
            stats.lastWriteMs = Math.round(performance.now() - started);
            active = null;
            schedule();
        }
    }
    return {
        persist: request,
        // Retry dirty state after failure; never let a duplicate bypass durability.
        barrier() {
            return pending?.promise ?? active?.promise ??
                (generation > persistedGeneration ? request() : Promise.resolve());
        },
        async flush() {
            do { await this.barrier(); } while (pending || active || generation > persistedGeneration);
        },
        diagnostics: () => ({ ...stats, generation, persistedGeneration,
            active: active !== null, pending: pending !== null })
    };
}
