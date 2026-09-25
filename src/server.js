import express from "express";
import cors from "cors";
import http from "http";
import { mkdir, readFile, rename, writeFile } from "fs/promises";
import { dirname, resolve } from "path";
import { Server } from "socket.io";

import {
    createHash,
    createPublicKey,
    randomBytes,
    randomUUID,
    verify as cryptoVerify
} from "crypto";


/*
 * =============================================================
 * CONFIG
 * =============================================================
 */

const PORT =
    Number(
        process.env.PORT ?? 3000
    );


/*
 * =============================================================
 * ANDROID APP LINKS
 * =============================================================
 *
 * Render already gives this service a public HTTPS host. Plexus
 * uses that host for verified Android App Links.
 *
 * ANDROID_APP_CERT_SHA256 may contain one fingerprint or multiple
 * comma-separated fingerprints (for example debug + release).
 */
const ANDROID_APP_PACKAGE =
    "com.plexus.app";


const ANDROID_APP_CERT_SHA256_FINGERPRINTS =
    String(
        process.env.ANDROID_APP_CERT_SHA256 ?? ""
    )
        .split(
            ","
        )
        .map(
            value =>
                value
                    .trim()
                    .toUpperCase()
        )
        .filter(
            value =>
                /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(
                    value
                )
        );


const AUTH_CHALLENGE_TTL_MS =
    2 * 60 * 1000;


const CLEANUP_INTERVAL_MS =
    60 * 1000;


/*
 * Server-side safety limit.
 *
 * This has NOTHING to do with Plexus mesh hop count.
 *
 * It only prevents one recipient from consuming unlimited
 * backend memory during development.
 */
const MAX_QUEUED_PACKETS_PER_RECIPIENT =
    1000;


/*
 * Connection requests / responses are tiny control packets,
 * but they still need a per-destination safety limit.
 */
const MAX_QUEUED_CONNECTION_CONTROL_PER_RECIPIENT =
    1000;


/*
 * Android currently creates connection request/response packets
 * with a maximum 30-day lifetime and tolerates up to 5 minutes
 * of future clock skew. Keep backend validation aligned with that
 * protocol contract.
 */
const CONNECTION_CONTROL_MAX_TTL_MS =
    30 * 24 * 60 * 60 * 1000;


const CONNECTION_CONTROL_MAX_FUTURE_SKEW_MS =
    5 * 60 * 1000;


const CONNECTION_CONTROL_MAX_DISPLAY_NAME_LENGTH =
    64;


/*
 * Durable backend state.
 *
 * Development:
 *     no REDIS_URL -> atomic JSON file on local disk
 *
 * Production:
 *     REDIS_URL set -> one atomic Redis snapshot
 *
 * Authentication/session routing remains intentionally in memory.
 */
const REDIS_URL =
    String(
        process.env.REDIS_URL ?? ""
    )
        .trim();


const REDIS_STATE_KEY =
    process.env.REDIS_STATE_KEY ??
    "plexus:server:durable-state:v1";


const LOCAL_STATE_FILE =
    resolve(
        process.env.PLEXUS_STATE_FILE ??
        ".plexus-state.json"
    );


/*
 * =============================================================
 * EXPRESS + SOCKET.IO
 * =============================================================
 */

const app =
    express();


app.use(
    cors({
        origin: "*"
    })
);


app.use(
    express.json({
        limit: "1mb"
    })
);


const httpServer =
    http.createServer(
        app
    );


const io =
    new Server(
        httpServer,
        {
            cors: {
                origin: "*"
            },

            maxHttpBufferSize:
                1024 * 1024
        }
    );


/*
 * =============================================================
 * RUNTIME STATE
 * =============================================================
 *
 * Online sockets and authentication challenges are ephemeral by
 * design.
 *
 * The following delivery state is durable:
 *
 * - queuedPackets
 * - deliveryVaccines
 * - pendingAntiPackets
 * - queuedConnectionRequests
 * - queuedConnectionResponses
 *
 * It is restored before the HTTP/Socket.IO server starts.
 */


/*
 * nodeId -> Set<socketId>
 *
 * A Set lets the same Plexus identity have more than one
 * active socket without corrupting the routing table.
 */
const onlineNodes =
    new Map();


/*
 * socketId -> authenticated identity
 *
 * {
 *     nodeId,
 *     signingPublicKey
 * }
 */
const authenticatedSockets =
    new Map();


/*
 * socketId -> pending challenge
 *
 * {
 *     challengeId,
 *     challenge,
 *     nodeId,
 *     signingPublicKey,
 *     createdAt,
 *     expiresAt
 * }
 */
const pendingAuthentications =
    new Map();


/*
 * destinationNodeId
 *      ->
 * Map<packetId, NearbyMeshPacket-like object>
 *
 * Messages remain queued until:
 *
 * signed anti-packet arrives
 *
 * OR
 *
 * message TTL expires.
 *
 * Merely emitting over Socket.IO does NOT count as delivery.
 */
const queuedPackets =
    new Map();


/*
 * messageId -> signed anti-packet
 *
 * This is the backend equivalent of the Android vaccine table.
 *
 * It prevents an already-delivered packet from being resurrected
 * on the internet path.
 */
const deliveryVaccines =
    new Map();


/*
 * sourceNodeId
 *      ->
 * Map<messageId, antiPacket>
 *
 * If the original sender is offline when the final recipient
 * confirms delivery, retain the anti-packet so the sender learns
 * about delivery when it reconnects.
 */
const pendingAntiPackets =
    new Map();


/*
 * recipientNodeId
 *      ->
 * Map<requestId, ConnectionRequestPacket-like object>
 *
 * Requests are kept until:
 *
 * - a signed response for that request reaches the backend, or
 * - the request expires.
 *
 * Re-emission on reconnect is safe because Android persists and
 * deduplicates requests by requestId.
 */
const queuedConnectionRequests =
    new Map();


/*
 * requesterNodeId
 *      ->
 * Map<responseId, ConnectionResponsePacket-like object>
 *
 * Responses are retained until expiry. Android deduplicates them
 * by responseId / request state, so reconnect delivery is safe.
 */
const queuedConnectionResponses =
    new Map();


/*
 * =============================================================
 * DURABLE STATE ENGINE
 * =============================================================
 *
 * To keep this prototype small and make the persistence backend
 * swappable, Plexus serializes the durable maps above.
 *
 * REDIS_URL present:
 *     snapshot is stored atomically in Redis.
 *
 * REDIS_URL absent:
 *     snapshot is stored atomically in a local JSON file.
 *
 * The local-file mode is useful for development and survives a
 * normal server process stop/start. Production deployments should
 * configure REDIS_URL because container filesystems may be
 * ephemeral.
 */

let redisClient =
    null;


let persistenceMode =
    REDIS_URL
        ? "redis"
        : "file";


let persistenceWriteChain =
    Promise.resolve();


function mapOfMapsToObject(
    outerMap
) {


    const result =
        {};


    for (
        const [
            outerKey,
            innerMap
        ]
        of outerMap
    ) {


        result[
            outerKey
        ] =
            Object.fromEntries(
                innerMap
            );
    }


    return result;
}


function objectToMapOfMaps(
    value
) {


    const result =
        new Map();


    if (
        !value ||
        typeof value !==
        "object" ||
        Array.isArray(
            value
        )
    ) {

        return result;
    }


    for (
        const [
            outerKey,
            innerValue
        ]
        of Object.entries(
            value
        )
    ) {


        if (
            !innerValue ||
            typeof innerValue !==
            "object" ||
            Array.isArray(
                innerValue
            )
        ) {

            continue;
        }


        result.set(
            outerKey,
            new Map(
                Object.entries(
                    innerValue
                )
            )
        );
    }


    return result;
}


function replaceMapContents(
    target,
    source
) {


    target.clear();


    for (
        const [
            key,
            value
        ]
        of source
    ) {

        target.set(
            key,
            value
        );
    }
}


function buildDurableSnapshot() {


    return {
        version: 2,
        savedAt: Date.now(),

        queuedPackets:
            mapOfMapsToObject(
                queuedPackets
            ),

        deliveryVaccines:
            Object.fromEntries(
                deliveryVaccines
            ),

        pendingAntiPackets:
            mapOfMapsToObject(
                pendingAntiPackets
            ),

        queuedConnectionRequests:
            mapOfMapsToObject(
                queuedConnectionRequests
            ),

        queuedConnectionResponses:
            mapOfMapsToObject(
                queuedConnectionResponses
            )
    };
}


function restoreDurableSnapshot(
    snapshot
) {


    if (
        !snapshot ||
        typeof snapshot !==
        "object" ||
        (
            snapshot.version !== 1 &&
            snapshot.version !== 2
        )
    ) {

        throw new Error(
            "Unsupported or invalid Plexus durable state"
        );
    }


    replaceMapContents(
        queuedPackets,
        objectToMapOfMaps(
            snapshot.queuedPackets
        )
    );


    replaceMapContents(
        deliveryVaccines,
        new Map(
            Object.entries(
                snapshot.deliveryVaccines ?? {}
            )
        )
    );


    replaceMapContents(
        pendingAntiPackets,
        objectToMapOfMaps(
            snapshot.pendingAntiPackets
        )
    );


    /*
     * Snapshot v1 did not contain connection control queues.
     * Missing fields intentionally restore as empty maps.
     */
    replaceMapContents(
        queuedConnectionRequests,
        objectToMapOfMaps(
            snapshot.queuedConnectionRequests
        )
    );


    replaceMapContents(
        queuedConnectionResponses,
        objectToMapOfMaps(
            snapshot.queuedConnectionResponses
        )
    );
}


async function initializeDurableState() {


    let serialized =
        null;


    if (
        REDIS_URL
    ) {


        let createClient;


        try {


            ({
                createClient
            } =
                await import(
                    "redis"
                ));


        } catch (
            error
        ) {


            throw new Error(
                "REDIS_URL is configured but the 'redis' package is not installed",
                {
                    cause: error
                }
            );
        }


        redisClient =
            createClient({
                url:
                    REDIS_URL
            });


        redisClient.on(
            "error",
            error => {


                console.error(
                    "[persistence] Redis error",
                    error
                );
            }
        );


        await redisClient
            .connect();


        serialized =
            await redisClient
                .get(
                    REDIS_STATE_KEY
                );


        persistenceMode =
            "redis";


    } else {


        try {


            serialized =
                await readFile(
                    LOCAL_STATE_FILE,
                    "utf8"
                );


        } catch (
            error
        ) {


            if (
                error?.code !==
                "ENOENT"
            ) {

                throw error;
            }
        }


        persistenceMode =
            "file";
    }


    if (
        serialized
    ) {


        const snapshot =
            JSON.parse(
                serialized
            );


        restoreDurableSnapshot(
            snapshot
        );
    }


    const changed =
        cleanupExpiredDurableState(
            Date.now()
        );


    if (
        changed
    ) {

        await persistDurableState();
    }


    console.log(
        `[persistence] ${persistenceMode} ready | ` +
        `queued=${countQueuedPackets()} | ` +
        `vaccines=${deliveryVaccines.size} | ` +
        `pendingAnti=${countPendingAntiPackets()} | ` +
        `connectionRequests=${countQueuedConnectionRequests()} | ` +
        `connectionResponses=${countQueuedConnectionResponses()}`
    );
}


function persistDurableState() {


    const serialized =
        JSON.stringify(
            buildDurableSnapshot()
        );


    persistenceWriteChain =
        persistenceWriteChain
            .catch(
                () => {}
            )
            .then(
                async () => {


                    if (
                        redisClient
                    ) {


                        await redisClient
                            .set(
                                REDIS_STATE_KEY,
                                serialized
                            );


                        return;
                    }


                    const directory =
                        dirname(
                            LOCAL_STATE_FILE
                        );


                    await mkdir(
                        directory,
                        {
                            recursive: true
                        }
                    );


                    const temporaryFile =
                        LOCAL_STATE_FILE +
                        ".tmp";


                    await writeFile(
                        temporaryFile,
                        serialized,
                        "utf8"
                    );


                    await rename(
                        temporaryFile,
                        LOCAL_STATE_FILE
                    );
                }
            );


    return persistenceWriteChain;
}


function countQueuedPackets() {


    let count =
        0;


    for (
        const queue
        of queuedPackets.values()
    ) {

        count +=
            queue.size;
    }


    return count;
}


function countPendingAntiPackets() {


    let count =
        0;


    for (
        const queue
        of pendingAntiPackets.values()
    ) {

        count +=
            queue.size;
    }


    return count;
}


function countQueuedConnectionRequests() {


    let count =
        0;


    for (
        const queue
        of queuedConnectionRequests.values()
    ) {

        count +=
            queue.size;
    }


    return count;
}


function countQueuedConnectionResponses() {


    let count =
        0;


    for (
        const queue
        of queuedConnectionResponses.values()
    ) {

        count +=
            queue.size;
    }


    return count;
}


function cleanupExpiredDurableState(
    now
) {


    let changed =
        false;


    for (
        const [
            destinationNodeId,
            queue
        ]
        of queuedPackets
    ) {


        for (
            const [
                packetId,
                packet
            ]
            of queue
        ) {


            if (
                Number(
                    packet?.expiresAt
                ) <= now
            ) {


                queue.delete(
                    packetId
                );


                changed =
                    true;
            }
        }


        if (
            queue.size === 0
        ) {


            queuedPackets.delete(
                destinationNodeId
            );


            changed =
                true;
        }
    }


    for (
        const [
            messageId,
            antiPacket
        ]
        of deliveryVaccines
    ) {


        if (
            Number(
                antiPacket?.expiresAt
            ) <= now
        ) {


            deliveryVaccines.delete(
                messageId
            );


            changed =
                true;
        }
    }


    for (
        const [
            sourceNodeId,
            queue
        ]
        of pendingAntiPackets
    ) {


        for (
            const [
                messageId,
                antiPacket
            ]
            of queue
        ) {


            if (
                Number(
                    antiPacket?.expiresAt
                ) <= now
            ) {


                queue.delete(
                    messageId
                );


                changed =
                    true;
            }
        }


        if (
            queue.size === 0
        ) {


            pendingAntiPackets.delete(
                sourceNodeId
            );


            changed =
                true;
        }
    }


    for (
        const [
            recipientNodeId,
            queue
        ]
        of queuedConnectionRequests
    ) {


        for (
            const [
                requestId,
                packet
            ]
            of queue
        ) {


            if (
                Number(
                    packet?.expiresAt
                ) <= now
            ) {


                queue.delete(
                    requestId
                );


                changed =
                    true;
            }
        }


        if (
            queue.size === 0
        ) {


            queuedConnectionRequests.delete(
                recipientNodeId
            );


            changed =
                true;
        }
    }


    for (
        const [
            requesterNodeId,
            queue
        ]
        of queuedConnectionResponses
    ) {


        for (
            const [
                responseId,
                packet
            ]
            of queue
        ) {


            if (
                Number(
                    packet?.expiresAt
                ) <= now
            ) {


                queue.delete(
                    responseId
                );


                changed =
                    true;
            }
        }


        if (
            queue.size === 0
        ) {


            queuedConnectionResponses.delete(
                requesterNodeId
            );


            changed =
                true;
        }
    }


    return changed;
}


/*
 * =============================================================
 * ANDROID APP LINK ASSOCIATION
 * =============================================================
 *
 * Android fetches this exact HTTPS path when verifying that this
 * web host is allowed to open links directly in com.plexus.app.
 *
 * IMPORTANT:
 * - no redirect from this HTTPS route
 * - Content-Type must be application/json
 * - fingerprint must match the APK signing certificate
 */
app.get(
    "/.well-known/assetlinks.json",
    (request, response) => {


        if (
            ANDROID_APP_CERT_SHA256_FINGERPRINTS.length === 0
        ) {


            return response
                .status(
                    503
                )
                .json({
                    error: "ANDROID_APP_CERT_SHA256_NOT_CONFIGURED"
                });
        }


        response
            .set(
                "Cache-Control",
                "public, max-age=300"
            )
            .json([
                {
                    relation: [
                        "delegate_permission/common.handle_all_urls"
                    ],

                    target: {
                        namespace: "android_app",
                        package_name: ANDROID_APP_PACKAGE,
                        sha256_cert_fingerprints:
                            ANDROID_APP_CERT_SHA256_FINGERPRINTS
                    }
                }
            ]);
    }
);


/*
 * =============================================================
 * CONNECT-LINK BROWSER FALLBACK
 * =============================================================
 *
 * When Plexus is installed and Android App Links verification has
 * succeeded, Android opens the app instead of this page.
 *
 * If Plexus is not installed (or verification has not completed),
 * the browser lands here instead of showing a 404. The identity is
 * stored in the URL fragment, so it is never sent to this server.
 */
app.get(
    "/connect",
    (request, response) => {


        response
            .set(
                "Cache-Control",
                "no-store"
            )
            .type(
                "html"
            )
            .send(
                `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Plexus Connect</title>
    <meta name="theme-color" content="#050505">
    <style>
        * { box-sizing: border-box; }
        html, body { margin: 0; min-height: 100%; background: #050505; color: #fff; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        body { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
        .card { width: min(440px, 100%); background: #101311; border: 1px solid #1d211e; border-radius: 24px; padding: 30px 26px; text-align: center; box-shadow: 0 18px 70px rgba(0,0,0,.45); }
        .mark { width: 58px; height: 58px; margin: 0 auto 18px; display: grid; place-items: center; border-radius: 18px; border: 1px solid rgba(77,255,139,.7); background: rgba(77,255,139,.08); color: #4dff8b; font-size: 28px; font-weight: 800; }
        h1 { margin: 0 0 10px; font-size: 28px; letter-spacing: -.5px; }
        p { margin: 0; color: #949a96; line-height: 1.55; }
        .hint { margin-top: 18px; color: #666d68; font-size: 13px; }
    </style>
</head>
<body>
    <main class="card">
        <div class="mark">P</div>
        <h1>Plexus connection link</h1>
        <p>Open this link on an Android device with Plexus installed to connect with this person.</p>
        <p class="hint">The shared Plexus identity stays in the URL fragment and is not sent to this server.</p>
    </main>
</body>
</html>`
            );
    }
);


/*
 * =============================================================
 * HEALTH ENDPOINT
 * =============================================================
 */

app.get(
    "/health",
    (request, response) => {


        response.json({
            ok: true,
            service: "plexus-server",
            onlineNodes:
                onlineNodes.size,
            queuedPackets:
                countQueuedPackets(),
            deliveryVaccines:
                deliveryVaccines.size,
            pendingAntiPackets:
                countPendingAntiPackets(),
            queuedConnectionRequests:
                countQueuedConnectionRequests(),
            queuedConnectionResponses:
                countQueuedConnectionResponses(),
            persistence:
                persistenceMode,
            timestamp:
                Date.now()
        });
    }
);


/*
 * =============================================================
 * SOCKET CONNECTION
 * =============================================================
 */

io.on(
    "connection",
    socket => {


        console.log(
            `[socket] connected ${socket.id}`
        );


        /*
         * =====================================================
         * AUTH STEP 1
         * =====================================================
         *
         * Android sends:
         *
         * {
         *     nodeId,
         *     signingPublicKey
         * }
         *
         * Server verifies:
         *
         * SHA256(signingPublicKey DER) == nodeId
         *
         * This only validates key/node binding.
         *
         * Possession of the private key is proven in STEP 2.
         */

        socket.on(
            "auth:init",
            (
                payload,
                acknowledgement
            ) => {


                try {


                    const nodeId =
                        normalizeNodeId(
                            payload?.nodeId
                        );


                    const signingPublicKey =
                        normalizeString(
                            payload?.signingPublicKey
                        );


                    if (
                        !nodeId ||
                        !signingPublicKey
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "INVALID_AUTH_IDENTITY"
                        );
                    }


                    if (
                        !isValidNodeIdentity(
                            nodeId,
                            signingPublicKey
                        )
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "NODE_ID_PUBLIC_KEY_MISMATCH"
                        );
                    }


                    const challengeId =
                        randomUUID();


                    const challenge =
                        randomBytes(
                            32
                        )
                            .toString(
                                "base64url"
                            );


                    const createdAt =
                        Date.now();


                    const expiresAt =
                        createdAt +
                        AUTH_CHALLENGE_TTL_MS;


                    pendingAuthentications.set(
                        socket.id,
                        {
                            challengeId,
                            challenge,
                            nodeId,
                            signingPublicKey,
                            createdAt,
                            expiresAt
                        }
                    );


                    socket.emit(
                        "auth:challenge",
                        {
                            challengeId,
                            challenge,
                            expiresAt
                        }
                    );


                    successfulAcknowledgement(
                        acknowledgement,
                        {
                            challengeIssued: true,
                            expiresAt
                        }
                    );


                    console.log(
                        `[auth] challenge -> ${shortNode(nodeId)}`
                    );


                } catch (
                    error
                ) {


                    console.error(
                        "[auth:init] error",
                        error
                    );


                    failAcknowledgement(
                        socket,
                        acknowledgement,
                        "AUTH_INIT_FAILED"
                    );
                }
            }
        );


        /*
         * =====================================================
         * AUTH STEP 2
         * =====================================================
         *
         * Android signs:
         *
         * PLEXUS_SERVER_AUTH_V1
         * |nodeId
         * |challengeId
         * |challenge
         *
         * using its ECDSA signing private key.
         */

        socket.on(
            "auth:proof",
            async (
                payload,
                acknowledgement
            ) => {


                try {


                    const pending =
                        pendingAuthentications.get(
                            socket.id
                        );


                    if (
                        !pending
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "NO_PENDING_CHALLENGE"
                        );
                    }


                    if (
                        Date.now() >
                        pending.expiresAt
                    ) {

                        pendingAuthentications.delete(
                            socket.id
                        );


                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "AUTH_CHALLENGE_EXPIRED"
                        );
                    }


                    const challengeId =
                        normalizeString(
                            payload?.challengeId
                        );


                    const signature =
                        normalizeString(
                            payload?.signature
                        );


                    if (
                        challengeId !==
                        pending.challengeId ||
                        !signature
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "INVALID_AUTH_PROOF"
                        );
                    }


                    const signedData =
                        buildServerAuthenticationMessage(
                            pending.nodeId,
                            pending.challengeId,
                            pending.challenge
                        );


                    const verified =
                        verifyEcdsaSignature(
                            signedData,
                            signature,
                            pending.signingPublicKey
                        );


                    if (
                        !verified
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "AUTH_SIGNATURE_INVALID"
                        );
                    }


                    /*
                     * Authentication succeeded.
                     */
                    pendingAuthentications.delete(
                        socket.id
                    );


                    authenticatedSockets.set(
                        socket.id,
                        {
                            nodeId:
                                pending.nodeId,

                            signingPublicKey:
                                pending.signingPublicKey
                        }
                    );


                    addOnlineSocket(
                        pending.nodeId,
                        socket.id
                    );


                    socket.emit(
                        "auth:success",
                        {
                            nodeId:
                                pending.nodeId
                        }
                    );


                    successfulAcknowledgement(
                        acknowledgement,
                        {
                            authenticated: true,
                            nodeId:
                                pending.nodeId
                        }
                    );


                    console.log(
                        `[auth] verified ✅ ${shortNode(pending.nodeId)}`
                    );


                    /*
                     * After authentication:
                     *
                     * 1. send delivery vaccines intended for this
                     *    original sender
                     *
                     * 2. then send still-live queued ciphertext
                     *
                     * Vaccines first helps suppress stale messages.
                     */

                    await flushPendingAntiPackets(
                        pending.nodeId
                    );


                    /*
                     * Control-plane packets are offered before queued
                     * chat ciphertext. In particular, an acceptance can
                     * establish trust before any message sent immediately
                     * after that acceptance arrives.
                     */
                    await flushConnectionRequests(
                        pending.nodeId
                    );


                    await flushConnectionResponses(
                        pending.nodeId
                    );


                    await flushQueuedPackets(
                        pending.nodeId
                    );


                } catch (
                    error
                ) {


                    console.error(
                        "[auth:proof] error",
                        error
                    );


                    failAcknowledgement(
                        socket,
                        acknowledgement,
                        "AUTH_PROOF_FAILED"
                    );
                }
            }
        );


        /*
         * =====================================================
         * INTERNET ENCRYPTED PACKET
         * =====================================================
         *
         * This is the SAME logical packet used by the mesh.
         *
         * Server does NOT decrypt encryptedPayload.
         */

        socket.on(
            "internet:packet",
            async (
                packet,
                acknowledgement
            ) => {


                try {


                    const authenticatedIdentity =
                        authenticatedSockets.get(
                            socket.id
                        );


                    if (
                        !authenticatedIdentity
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "NOT_AUTHENTICATED"
                        );
                    }


                    const validation =
                        validateMeshPacket(
                            packet
                        );


                    if (
                        !validation.valid
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            validation.reason
                        );
                    }


                    const packetId =
                        normalizeString(
                            packet.packetId
                        );


                    const sourceNodeId =
                        normalizeNodeId(
                            packet.sourceNodeId
                        );


                    const destinationNodeId =
                        normalizeNodeId(
                            packet.destinationNodeId
                        );


                    /*
                     * A client may only originate internet packets
                     * whose source identity is itself.
                     *
                     * Later, if we intentionally allow internet
                     * relay uploads from mesh nodes, that can become
                     * a separate signed protocol.
                     */
                    if (
                        sourceNodeId !==
                        authenticatedIdentity.nodeId
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "SOURCE_IDENTITY_MISMATCH"
                        );
                    }


                    /*
                     * Already delivered?
                     *
                     * Don't resurrect the heavy payload.
                     */
                    const vaccine =
                        deliveryVaccines.get(
                            packetId
                        );


                    if (
                        vaccine &&
                        isAntiPacketActive(
                            vaccine
                        ) &&
                        antiPacketMatchesMeshPacket(
                            vaccine,
                            packet
                        )
                    ) {


                        successfulAcknowledgement(
                            acknowledgement,
                            {
                                accepted: false,
                                deliveredAlready: true
                            }
                        );


                        socket.emit(
                            "internet:anti_packet",
                            vaccine
                        );


                        return;
                    }


                    /*
                     * Persist in backend queue FIRST.
                     *
                     * In this version "persist" means in-memory.
                     *
                     * Later this exact interface can move to Redis.
                     */
                    queueMeshPacket(
                        destinationNodeId,
                        packet
                    );


                    /*
                     * Durability is established before we acknowledge
                     * the sender. If this write fails, the handler falls
                     * into the catch block and the client will retry.
                     */
                    await persistDurableState();


                    /*
                     * If destination is online, immediately offer
                     * it the ciphertext.
                     *
                     * IMPORTANT:
                     *
                     * We DO NOT remove it from the queue merely
                     * because Socket.IO accepted emit().
                     *
                     * Queue deletion requires the recipient's
                     * signed anti-packet.
                     */
                    const deliveredToSockets =
                        emitToNode(
                            destinationNodeId,
                            "internet:packet",
                            packet
                        );


                    successfulAcknowledgement(
                        acknowledgement,
                        {
                            accepted: true,

                            queued: true,

                            destinationOnline:
                                deliveredToSockets > 0,

                            deliveredToSockets
                        }
                    );


                    console.log(
                        `[packet] ${packetId.slice(0, 8)} ` +
                        `${shortNode(sourceNodeId)} -> ` +
                        `${shortNode(destinationNodeId)} ` +
                        `online=${deliveredToSockets > 0}`
                    );


                } catch (
                    error
                ) {


                    console.error(
                        "[internet:packet] error",
                        error
                    );


                    failAcknowledgement(
                        socket,
                        acknowledgement,
                        "INTERNET_PACKET_FAILED"
                    );
                }
            }
        );


        /*
         * =====================================================
         * SIGNED DELIVERY ANTI-PACKET
         * =====================================================
         *
         * Final recipient signs proof of DEVICE delivery.
         *
         * Server verifies signature before deleting ciphertext.
         *
         * This is NOT a read receipt.
         */

        socket.on(
            "internet:anti_packet",
            async (
                antiPacket,
                acknowledgement
            ) => {


                try {


                    const authenticatedIdentity =
                        authenticatedSockets.get(
                            socket.id
                        );


                    if (
                        !authenticatedIdentity
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "NOT_AUTHENTICATED"
                        );
                    }


                    const validation =
                        validateAndVerifyAntiPacket(
                            antiPacket
                        );


                    if (
                        !validation.valid
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            validation.reason
                        );
                    }


                    const messageId =
                        normalizeString(
                            antiPacket.messageId
                        );


                    const sourceNodeId =
                        normalizeNodeId(
                            antiPacket.sourceNodeId
                        );


                    const recipientNodeId =
                        normalizeNodeId(
                            antiPacket.recipientNodeId
                        );


                    /*
                     * On the internet path, the final recipient
                     * should normally submit its own delivery proof.
                     *
                     * We require that here.
                     *
                     * Mesh relays may still propagate anti-packets
                     * locally without this restriction.
                     */
                    if (
                        recipientNodeId !==
                        authenticatedIdentity.nodeId
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "ANTI_PACKET_NOT_FROM_RECIPIENT"
                        );
                    }


                    /*
                     * If the backend still holds the corresponding
                     * ciphertext, ensure the anti-packet identifies
                     * the exact source/destination pair.
                     */
                    const queuedPacket =
                        findQueuedPacket(
                            recipientNodeId,
                            messageId
                        );


                    if (
                        queuedPacket &&
                        !antiPacketMatchesMeshPacket(
                            antiPacket,
                            queuedPacket
                        )
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "ANTI_PACKET_MESSAGE_MISMATCH"
                        );
                    }


                    /*
                     * Store backend vaccine first.
                     */
                    deliveryVaccines.set(
                        messageId,
                        antiPacket
                    );


                    /*
                     * Now remove heavy encrypted queue copy.
                     */
                    deleteQueuedPacket(
                        recipientNodeId,
                        messageId
                    );


                    /*
                     * Preserve the anti-packet for the original
                     * sender in case that sender is currently
                     * offline.
                     */
                    queueAntiPacketForSource(
                        sourceNodeId,
                        antiPacket
                    );


                    /*
                     * The signed vaccine, queue deletion and pending
                     * sender notification become durable as one
                     * snapshot before we acknowledge the recipient.
                     */
                    await persistDurableState();


                    /*
                     * If original sender is online, send delivery
                     * proof immediately.
                     */
                    const deliveredToSourceSockets =
                        emitToNode(
                            sourceNodeId,
                            "internet:anti_packet",
                            antiPacket
                        );


                    successfulAcknowledgement(
                        acknowledgement,
                        {
                            accepted: true,
                            messageId,
                            deliveredToSourceSockets
                        }
                    );


                    console.log(
                        `[anti] ${messageId.slice(0, 8)} ` +
                        `recipient=${shortNode(recipientNodeId)} ✅`
                    );


                } catch (
                    error
                ) {


                    console.error(
                        "[internet:anti_packet] error",
                        error
                    );


                    failAcknowledgement(
                        socket,
                        acknowledgement,
                        "ANTI_PACKET_FAILED"
                    );
                }
            }
        );


        /*
         * =====================================================
         * SIGNED CONNECTION REQUEST
         * =====================================================
         *
         * The backend can read public identity metadata, but it
         * cannot forge a request because the entire request is
         * signed by senderNodeId's Android-keystore identity key.
         */

        socket.on(
            "internet:connection_request",
            async (
                packet,
                acknowledgement
            ) => {


                try {


                    const authenticatedIdentity =
                        authenticatedSockets.get(
                            socket.id
                        );


                    if (
                        !authenticatedIdentity
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "NOT_AUTHENTICATED"
                        );
                    }


                    const validation =
                        validateAndVerifyConnectionRequest(
                            packet
                        );


                    if (
                        !validation.valid
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            validation.reason
                        );
                    }


                    const senderNodeId =
                        normalizeNodeId(
                            packet.senderNodeId
                        );


                    const recipientNodeId =
                        normalizeNodeId(
                            packet.recipientNodeId
                        );


                    if (
                        senderNodeId !==
                        authenticatedIdentity.nodeId
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "CONNECTION_REQUEST_SOURCE_MISMATCH"
                        );
                    }


                    const queued =
                        queueConnectionRequest(
                            recipientNodeId,
                            packet
                        );


                    /*
                     * Persist FIRST. Only after the durable write succeeds
                     * do we acknowledge the sender or offer the request to
                     * an online recipient.
                     */
                    if (
                        queued
                    ) {

                        await persistDurableState();
                    }


                    const deliveredToSockets =
                        emitToNode(
                            recipientNodeId,
                            "internet:connection_request",
                            packet
                        );


                    successfulAcknowledgement(
                        acknowledgement,
                        {
                            accepted: true,
                            duplicate:
                                !queued,
                            queued: true,
                            destinationOnline:
                                deliveredToSockets > 0,
                            deliveredToSockets
                        }
                    );


                    console.log(
                        `[connect-request] ${packet.requestId.slice(0, 8)} ` +
                        `${shortNode(senderNodeId)} -> ` +
                        `${shortNode(recipientNodeId)} ` +
                        `duplicate=${!queued} ` +
                        `online=${deliveredToSockets > 0}`
                    );


                } catch (
                    error
                ) {


                    console.error(
                        "[internet:connection_request] error",
                        error
                    );


                    failAcknowledgement(
                        socket,
                        acknowledgement,
                        "CONNECTION_REQUEST_FAILED"
                    );
                }
            }
        );


        /*
         * =====================================================
         * SIGNED CONNECTION RESPONSE
         * =====================================================
         *
         * ACCEPTED / DECLINED is signed by the responder.
         *
         * A response may legitimately reach the backend even if
         * the original request arrived to the responder through
         * Nearby rather than the internet, so the server does NOT
         * require a matching queued request to exist.
         */

        socket.on(
            "internet:connection_response",
            async (
                packet,
                acknowledgement
            ) => {


                try {


                    const authenticatedIdentity =
                        authenticatedSockets.get(
                            socket.id
                        );


                    if (
                        !authenticatedIdentity
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "NOT_AUTHENTICATED"
                        );
                    }


                    const validation =
                        validateAndVerifyConnectionResponse(
                            packet
                        );


                    if (
                        !validation.valid
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            validation.reason
                        );
                    }


                    const requesterNodeId =
                        normalizeNodeId(
                            packet.requesterNodeId
                        );


                    const responderNodeId =
                        normalizeNodeId(
                            packet.responderNodeId
                        );


                    if (
                        responderNodeId !==
                        authenticatedIdentity.nodeId
                    ) {

                        return failAcknowledgement(
                            socket,
                            acknowledgement,
                            "CONNECTION_RESPONSE_SOURCE_MISMATCH"
                        );
                    }


                    const queued =
                        queueConnectionResponse(
                            requesterNodeId,
                            packet
                        );


                    /*
                     * A valid signed response completes the responder-side
                     * lifecycle of the original request. Remove the server's
                     * queued copy if it came through this backend.
                     */
                    const removedOriginalRequest =
                        deleteQueuedConnectionRequest(
                            responderNodeId,
                            packet.requestId
                        );


                    if (
                        queued ||
                        removedOriginalRequest
                    ) {

                        await persistDurableState();
                    }


                    const deliveredToSockets =
                        emitToNode(
                            requesterNodeId,
                            "internet:connection_response",
                            packet
                        );


                    successfulAcknowledgement(
                        acknowledgement,
                        {
                            accepted: true,
                            duplicate:
                                !queued,
                            queued: true,
                            destinationOnline:
                                deliveredToSockets > 0,
                            deliveredToSockets
                        }
                    );


                    console.log(
                        `[connect-response] ${packet.responseId.slice(0, 8)} ` +
                        `${shortNode(responderNodeId)} -> ` +
                        `${shortNode(requesterNodeId)} ` +
                        `${packet.response} ` +
                        `duplicate=${!queued} ` +
                        `online=${deliveredToSockets > 0}`
                    );


                } catch (
                    error
                ) {


                    console.error(
                        "[internet:connection_response] error",
                        error
                    );


                    failAcknowledgement(
                        socket,
                        acknowledgement,
                        "CONNECTION_RESPONSE_FAILED"
                    );
                }
            }
        );


        /*
         * =====================================================
         * DISCONNECT
         * =====================================================
         */

        socket.on(
            "disconnect",
            reason => {


                const identity =
                    authenticatedSockets.get(
                        socket.id
                    );


                if (
                    identity
                ) {

                    removeOnlineSocket(
                        identity.nodeId,
                        socket.id
                    );


                    authenticatedSockets.delete(
                        socket.id
                    );
                }


                pendingAuthentications.delete(
                    socket.id
                );


                console.log(
                    `[socket] disconnected ${socket.id} | ${reason}`
                );
            }
        );
    }
);


/*
 * =============================================================
 * AUTH HELPERS
 * =============================================================
 */

function buildServerAuthenticationMessage(
    nodeId,
    challengeId,
    challenge
) {


    return Buffer.from(

        "PLEXUS_SERVER_AUTH_V1|" +
        nodeId +
        "|" +
        challengeId +
        "|" +
        challenge,

        "utf8"
    );
}


function isValidNodeIdentity(
    nodeId,
    signingPublicKey
) {


    try {


        const publicKeyBytes =
            Buffer.from(
                signingPublicKey,
                "base64"
            );


        const calculatedNodeId =
            createHash(
                "sha256"
            )
                .update(
                    publicKeyBytes
                )
                .digest(
                    "hex"
                );


        return calculatedNodeId ===
            normalizeNodeId(
                nodeId
            );


    } catch {


        return false;
    }
}


function verifyEcdsaSignature(
    data,
    signatureBase64,
    publicKeyBase64
) {


    try {


        const publicKey =
            createPublicKey({
                key:
                    Buffer.from(
                        publicKeyBase64,
                        "base64"
                    ),

                format:
                    "der",

                type:
                    "spki"
            });


        const signature =
            Buffer.from(
                signatureBase64,
                "base64"
            );


        return cryptoVerify(
            "sha256",
            data,
            publicKey,
            signature
        );


    } catch (
        error
    ) {


        console.error(
            "[crypto] signature verification failed",
            error.message
        );


        return false;
    }
}


/*
 * =============================================================
 * ANTI-PACKET CRYPTO
 * =============================================================
 */

function buildAntiPacketSigningPayload(
    antiPacket
) {


    return Buffer.from(

        "PLEXUS_DELIVERY_V1|" +
        antiPacket.messageId +
        "|" +
        normalizeNodeId(
            antiPacket.sourceNodeId
        ) +
        "|" +
        normalizeNodeId(
            antiPacket.recipientNodeId
        ) +
        "|" +
        antiPacket.deliveredAt +
        "|" +
        antiPacket.expiresAt,

        "utf8"
    );
}


function validateAndVerifyAntiPacket(
    antiPacket
) {


    if (
        !antiPacket ||
        typeof antiPacket !==
        "object"
    ) {

        return invalid(
            "INVALID_ANTI_PACKET"
        );
    }


    const messageId =
        normalizeString(
            antiPacket.messageId
        );


    const sourceNodeId =
        normalizeNodeId(
            antiPacket.sourceNodeId
        );


    const recipientNodeId =
        normalizeNodeId(
            antiPacket.recipientNodeId
        );


    const recipientSigningPublicKey =
        normalizeString(
            antiPacket.recipientSigningPublicKey
        );


    const signature =
        normalizeString(
            antiPacket.signature
        );


    const deliveredAt =
        Number(
            antiPacket.deliveredAt
        );


    const expiresAt =
        Number(
            antiPacket.expiresAt
        );


    if (
        !messageId ||
        !sourceNodeId ||
        !recipientNodeId ||
        !recipientSigningPublicKey ||
        !signature ||
        !Number.isSafeInteger(
            deliveredAt
        ) ||
        !Number.isSafeInteger(
            expiresAt
        ) ||
        deliveredAt <= 0 ||
        expiresAt <= deliveredAt
    ) {

        return invalid(
            "INVALID_ANTI_PACKET_FIELDS"
        );
    }


    if (
        Date.now() >
        expiresAt
    ) {

        return invalid(
            "ANTI_PACKET_EXPIRED"
        );
    }


    if (
        !isValidNodeIdentity(
            recipientNodeId,
            recipientSigningPublicKey
        )
    ) {

        return invalid(
            "ANTI_PACKET_IDENTITY_MISMATCH"
        );
    }


    const signatureValid =
        verifyEcdsaSignature(

            buildAntiPacketSigningPayload(
                {
                    ...antiPacket,

                    sourceNodeId,

                    recipientNodeId
                }
            ),

            signature,

            recipientSigningPublicKey
        );


    if (
        !signatureValid
    ) {

        return invalid(
            "ANTI_PACKET_SIGNATURE_INVALID"
        );
    }


    return valid();
}


/*
 * =============================================================
 * CONNECTION CONTROL CRYPTO
 * =============================================================
 */

function appendLengthPrefixed(
    value
) {


    const stringValue =
        String(
            value
        );


    return (
        Buffer.byteLength(
            stringValue,
            "utf8"
        ) +
        ":" +
        stringValue +
        "|"
    );
}


function buildConnectionRequestSigningPayload(
    packet
) {


    return Buffer.from(

        "PLEXUS_CONNECTION_REQUEST_V1|" +
        appendLengthPrefixed(
            packet.requestId
        ) +
        appendLengthPrefixed(
            packet.senderNodeId
        ) +
        appendLengthPrefixed(
            packet.recipientNodeId
        ) +
        appendLengthPrefixed(
            packet.senderDisplayName
        ) +
        appendLengthPrefixed(
            packet.senderSigningPublicKey
        ) +
        appendLengthPrefixed(
            packet.senderAgreementPublicKey
        ) +
        appendLengthPrefixed(
            packet.createdAt
        ) +
        appendLengthPrefixed(
            packet.expiresAt
        ),

        "utf8"
    );
}


function buildConnectionResponseSigningPayload(
    packet
) {


    return Buffer.from(

        "PLEXUS_CONNECTION_RESPONSE_V1|" +
        appendLengthPrefixed(
            packet.requestId
        ) +
        appendLengthPrefixed(
            packet.responseId
        ) +
        appendLengthPrefixed(
            packet.requesterNodeId
        ) +
        appendLengthPrefixed(
            packet.responderNodeId
        ) +
        appendLengthPrefixed(
            packet.response
        ) +
        appendLengthPrefixed(
            packet.responderDisplayName
        ) +
        appendLengthPrefixed(
            packet.responderSigningPublicKey
        ) +
        appendLengthPrefixed(
            packet.responderAgreementPublicKey
        ) +
        appendLengthPrefixed(
            packet.createdAt
        ) +
        appendLengthPrefixed(
            packet.expiresAt
        ),

        "utf8"
    );
}


function isUuid(
    value
) {


    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
        .test(
            normalizeString(
                value
            )
        );
}


function validateConnectionControlTimes(
    createdAt,
    expiresAt,
    now = Date.now()
) {


    if (
        !Number.isSafeInteger(
            createdAt
        ) ||
        !Number.isSafeInteger(
            expiresAt
        ) ||
        createdAt <= 0 ||
        expiresAt <= createdAt
    ) {

        return invalid(
            "INVALID_CONNECTION_CONTROL_TIMESTAMPS"
        );
    }


    if (
        createdAt >
        now + CONNECTION_CONTROL_MAX_FUTURE_SKEW_MS
    ) {

        return invalid(
            "CONNECTION_CONTROL_FROM_FUTURE"
        );
    }


    if (
        expiresAt - createdAt >
        CONNECTION_CONTROL_MAX_TTL_MS
    ) {

        return invalid(
            "CONNECTION_CONTROL_TTL_TOO_LARGE"
        );
    }


    if (
        expiresAt <= now
    ) {

        return invalid(
            "CONNECTION_CONTROL_EXPIRED"
        );
    }


    return valid();
}


function validateAndVerifyConnectionRequest(
    packet
) {


    if (
        !packet ||
        typeof packet !==
        "object"
    ) {

        return invalid(
            "INVALID_CONNECTION_REQUEST"
        );
    }


    if (
        packet.type !==
            "connection_request" ||
        Number(
            packet.version
        ) !== 1
    ) {

        return invalid(
            "UNSUPPORTED_CONNECTION_REQUEST"
        );
    }


    const requestId =
        normalizeString(
            packet.requestId
        );


    const senderNodeId =
        normalizeNodeId(
            packet.senderNodeId
        );


    const recipientNodeId =
        normalizeNodeId(
            packet.recipientNodeId
        );


    const senderDisplayName =
        normalizeString(
            packet.senderDisplayName
        );


    const senderSigningPublicKey =
        normalizeString(
            packet.senderSigningPublicKey
        );


    const senderAgreementPublicKey =
        normalizeString(
            packet.senderAgreementPublicKey
        );


    const signature =
        normalizeString(
            packet.signature
        );


    const createdAt =
        Number(
            packet.createdAt
        );


    const expiresAt =
        Number(
            packet.expiresAt
        );


    if (
        !requestId ||
        !isUuid(
            requestId
        ) ||
        !senderNodeId ||
        !recipientNodeId ||
        senderNodeId === recipientNodeId ||
        !senderDisplayName ||
        senderDisplayName.length >
            CONNECTION_CONTROL_MAX_DISPLAY_NAME_LENGTH ||
        !senderSigningPublicKey ||
        !senderAgreementPublicKey ||
        !signature
    ) {

        return invalid(
            "INVALID_CONNECTION_REQUEST_FIELDS"
        );
    }


    const timeValidation =
        validateConnectionControlTimes(
            createdAt,
            expiresAt
        );


    if (
        !timeValidation.valid
    ) {

        return timeValidation;
    }


    if (
        !isValidNodeIdentity(
            senderNodeId,
            senderSigningPublicKey
        )
    ) {

        return invalid(
            "CONNECTION_REQUEST_IDENTITY_MISMATCH"
        );
    }


    const signatureValid =
        verifyEcdsaSignature(

            buildConnectionRequestSigningPayload(
                packet
            ),

            signature,

            senderSigningPublicKey
        );


    if (
        !signatureValid
    ) {

        return invalid(
            "CONNECTION_REQUEST_SIGNATURE_INVALID"
        );
    }


    return valid();
}


function validateAndVerifyConnectionResponse(
    packet
) {


    if (
        !packet ||
        typeof packet !==
        "object"
    ) {

        return invalid(
            "INVALID_CONNECTION_RESPONSE"
        );
    }


    if (
        packet.type !==
            "connection_response" ||
        Number(
            packet.version
        ) !== 1
    ) {

        return invalid(
            "UNSUPPORTED_CONNECTION_RESPONSE"
        );
    }


    const requestId =
        normalizeString(
            packet.requestId
        );


    const responseId =
        normalizeString(
            packet.responseId
        );


    const requesterNodeId =
        normalizeNodeId(
            packet.requesterNodeId
        );


    const responderNodeId =
        normalizeNodeId(
            packet.responderNodeId
        );


    const response =
        normalizeString(
            packet.response
        );


    const responderDisplayName =
        normalizeString(
            packet.responderDisplayName
        );


    const responderSigningPublicKey =
        normalizeString(
            packet.responderSigningPublicKey
        );


    const responderAgreementPublicKey =
        normalizeString(
            packet.responderAgreementPublicKey
        );


    const signature =
        normalizeString(
            packet.signature
        );


    const createdAt =
        Number(
            packet.createdAt
        );


    const expiresAt =
        Number(
            packet.expiresAt
        );


    if (
        !requestId ||
        !isUuid(
            requestId
        ) ||
        !responseId ||
        !isUuid(
            responseId
        ) ||
        !requesterNodeId ||
        !responderNodeId ||
        requesterNodeId === responderNodeId ||
        (
            response !== "ACCEPTED" &&
            response !== "DECLINED"
        ) ||
        !responderDisplayName ||
        responderDisplayName.length >
            CONNECTION_CONTROL_MAX_DISPLAY_NAME_LENGTH ||
        !responderSigningPublicKey ||
        !responderAgreementPublicKey ||
        !signature
    ) {

        return invalid(
            "INVALID_CONNECTION_RESPONSE_FIELDS"
        );
    }


    const timeValidation =
        validateConnectionControlTimes(
            createdAt,
            expiresAt
        );


    if (
        !timeValidation.valid
    ) {

        return timeValidation;
    }


    if (
        !isValidNodeIdentity(
            responderNodeId,
            responderSigningPublicKey
        )
    ) {

        return invalid(
            "CONNECTION_RESPONSE_IDENTITY_MISMATCH"
        );
    }


    const signatureValid =
        verifyEcdsaSignature(

            buildConnectionResponseSigningPayload(
                packet
            ),

            signature,

            responderSigningPublicKey
        );


    if (
        !signatureValid
    ) {

        return invalid(
            "CONNECTION_RESPONSE_SIGNATURE_INVALID"
        );
    }


    return valid();
}


/*
 * =============================================================
 * MESH PACKET VALIDATION
 * =============================================================
 */

function validateMeshPacket(
    packet
) {


    if (
        !packet ||
        typeof packet !==
        "object"
    ) {

        return invalid(
            "INVALID_MESH_PACKET"
        );
    }


    const packetId =
        normalizeString(
            packet.packetId
        );


    const sourceNodeId =
        normalizeNodeId(
            packet.sourceNodeId
        );


    const destinationNodeId =
        normalizeNodeId(
            packet.destinationNodeId
        );


    const encryptedPayload =
        normalizeString(
            packet.encryptedPayload
        );


    const createdAt =
        Number(
            packet.createdAt
        );


    const expiresAt =
        Number(
            packet.expiresAt
        );


    const hopCount =
        Number(
            packet.hopCount
        );


    if (
        !packetId ||
        !sourceNodeId ||
        !destinationNodeId ||
        !encryptedPayload ||
        !Number.isSafeInteger(
            createdAt
        ) ||
        !Number.isSafeInteger(
            expiresAt
        ) ||
        !Number.isSafeInteger(
            hopCount
        ) ||
        createdAt <= 0 ||
        expiresAt <= createdAt ||
        hopCount < 0
    ) {

        return invalid(
            "INVALID_MESH_PACKET_FIELDS"
        );
    }


    /*
     * Hop count is informational only.
     *
     * There is deliberately NO maximum-hop check.
     */
    if (
        Date.now() >
        expiresAt
    ) {

        return invalid(
            "MESH_PACKET_EXPIRED"
        );
    }


    return valid();
}


/*
 * =============================================================
 * ONLINE NODE ROUTING
 * =============================================================
 */

function addOnlineSocket(
    nodeId,
    socketId
) {


    const normalized =
        normalizeNodeId(
            nodeId
        );


    let sockets =
        onlineNodes.get(
            normalized
        );


    if (
        !sockets
    ) {

        sockets =
            new Set();


        onlineNodes.set(
            normalized,
            sockets
        );
    }


    sockets.add(
        socketId
    );
}


function removeOnlineSocket(
    nodeId,
    socketId
) {


    const normalized =
        normalizeNodeId(
            nodeId
        );


    const sockets =
        onlineNodes.get(
            normalized
        );


    if (
        !sockets
    ) {

        return;
    }


    sockets.delete(
        socketId
    );


    if (
        sockets.size === 0
    ) {

        onlineNodes.delete(
            normalized
        );
    }
}


function emitToNode(
    nodeId,
    eventName,
    payload
) {


    const sockets =
        onlineNodes.get(
            normalizeNodeId(
                nodeId
            )
        );


    if (
        !sockets ||
        sockets.size === 0
    ) {

        return 0;
    }


    let sent =
        0;


    for (
        const socketId
        of sockets
    ) {


        const destinationSocket =
            io.sockets.sockets.get(
                socketId
            );


        if (
            destinationSocket
        ) {

            destinationSocket.emit(
                eventName,
                payload
            );


            sent += 1;
        }
    }


    return sent;
}


/*
 * =============================================================
 * BACKEND MESSAGE QUEUE
 * =============================================================
 */

function queueMeshPacket(
    destinationNodeId,
    packet
) {


    const destination =
        normalizeNodeId(
            destinationNodeId
        );


    let queue =
        queuedPackets.get(
            destination
        );


    if (
        !queue
    ) {

        queue =
            new Map();


        queuedPackets.set(
            destination,
            queue
        );
    }


    /*
     * packetId deduplication.
     */
    queue.set(
        packet.packetId,
        packet
    );


    /*
     * Backend memory protection only.
     *
     * NOT a mesh hop limit.
     */
    while (
        queue.size >
        MAX_QUEUED_PACKETS_PER_RECIPIENT
    ) {


        const oldestPacketId =
            queue
                .keys()
                .next()
                .value;


        if (
            oldestPacketId ===
            undefined
        ) {

            break;
        }


        queue.delete(
            oldestPacketId
        );
    }
}


function findQueuedPacket(
    destinationNodeId,
    packetId
) {


    const queue =
        queuedPackets.get(
            normalizeNodeId(
                destinationNodeId
            )
        );


    return queue?.get(
        packetId
    ) ?? null;
}


function deleteQueuedPacket(
    destinationNodeId,
    packetId
) {


    const destination =
        normalizeNodeId(
            destinationNodeId
        );


    const queue =
        queuedPackets.get(
            destination
        );


    if (
        !queue
    ) {

        return false;
    }


    const deleted =
        queue.delete(
            packetId
        );


    if (
        queue.size === 0
    ) {

        queuedPackets.delete(
            destination
        );
    }


    return deleted;
}


async function flushQueuedPackets(
    nodeId
) {


    const destination =
        normalizeNodeId(
            nodeId
        );


    const queue =
        queuedPackets.get(
            destination
        );


    if (
        !queue
    ) {

        return;
    }


    const now =
        Date.now();


    let changed =
        false;


    for (
        const [
            packetId,
            packet
        ]
        of queue
    ) {


        if (
            Number(
                packet.expiresAt
            ) <= now
        ) {


            queue.delete(
                packetId
            );


            changed =
                true;


            continue;
        }


        const vaccine =
            deliveryVaccines.get(
                packetId
            );


        if (
            vaccine &&
            isAntiPacketActive(
                vaccine
            ) &&
            antiPacketMatchesMeshPacket(
                vaccine,
                packet
            )
        ) {


            queue.delete(
                packetId
            );


            changed =
                true;


            continue;
        }


        emitToNode(
            destination,
            "internet:packet",
            packet
        );
    }


    if (
        queue.size === 0
    ) {


        queuedPackets.delete(
            destination
        );


        changed =
            true;
    }


    if (
        changed
    ) {

        await persistDurableState();
    }
}


/*
 * =============================================================
 * DELIVERY VACCINE ROUTING
 * =============================================================
 */

function queueAntiPacketForSource(
    sourceNodeId,
    antiPacket
) {


    const source =
        normalizeNodeId(
            sourceNodeId
        );


    let queue =
        pendingAntiPackets.get(
            source
        );


    if (
        !queue
    ) {

        queue =
            new Map();


        pendingAntiPackets.set(
            source,
            queue
        );
    }


    queue.set(
        antiPacket.messageId,
        antiPacket
    );
}


async function flushPendingAntiPackets(
    nodeId
) {


    const source =
        normalizeNodeId(
            nodeId
        );


    const queue =
        pendingAntiPackets.get(
            source
        );


    if (
        !queue
    ) {

        return;
    }


    const now =
        Date.now();


    let changed =
        false;


    for (
        const [
            messageId,
            antiPacket
        ]
        of queue
    ) {


        if (
            Number(
                antiPacket.expiresAt
            ) <= now
        ) {


            queue.delete(
                messageId
            );


            changed =
                true;


            continue;
        }


        emitToNode(
            source,
            "internet:anti_packet",
            antiPacket
        );
    }


    if (
        queue.size === 0
    ) {


        pendingAntiPackets.delete(
            source
        );


        changed =
            true;
    }


    if (
        changed
    ) {

        await persistDurableState();
    }


    /*
     * We deliberately keep active anti-packets here.
     *
     * The sender may reconnect again before expiry.
     * Duplicate suppression on Android makes resending safe.
     */
}


/*
 * =============================================================
 * CONNECTION CONTROL QUEUES
 * =============================================================
 */

function queueConnectionControlPacket(
    outerMap,
    destinationNodeId,
    packetId,
    packet
) {


    const destination =
        normalizeNodeId(
            destinationNodeId
        );


    let queue =
        outerMap.get(
            destination
        );


    if (
        !queue
    ) {

        queue =
            new Map();


        outerMap.set(
            destination,
            queue
        );
    }


    /*
     * Strict first-wins deduplication.
     *
     * If the same signed request/response reaches us again through
     * retries, do not mutate the already durable copy.
     */
    if (
        queue.has(
            packetId
        )
    ) {

        return false;
    }


    queue.set(
        packetId,
        packet
    );


    while (
        queue.size >
        MAX_QUEUED_CONNECTION_CONTROL_PER_RECIPIENT
    ) {


        const oldestPacketId =
            queue
                .keys()
                .next()
                .value;


        if (
            oldestPacketId ===
            undefined
        ) {

            break;
        }


        queue.delete(
            oldestPacketId
        );
    }


    return true;
}


function queueConnectionRequest(
    recipientNodeId,
    packet
) {


    return queueConnectionControlPacket(
        queuedConnectionRequests,
        recipientNodeId,
        packet.requestId,
        packet
    );
}


function queueConnectionResponse(
    requesterNodeId,
    packet
) {


    return queueConnectionControlPacket(
        queuedConnectionResponses,
        requesterNodeId,
        packet.responseId,
        packet
    );
}


function deleteQueuedConnectionRequest(
    recipientNodeId,
    requestId
) {


    const recipient =
        normalizeNodeId(
            recipientNodeId
        );


    const queue =
        queuedConnectionRequests.get(
            recipient
        );


    if (
        !queue
    ) {

        return false;
    }


    const deleted =
        queue.delete(
            requestId
        );


    if (
        queue.size === 0
    ) {

        queuedConnectionRequests.delete(
            recipient
        );
    }


    return deleted;
}


async function flushConnectionRequests(
    nodeId
) {


    const recipient =
        normalizeNodeId(
            nodeId
        );


    const queue =
        queuedConnectionRequests.get(
            recipient
        );


    if (
        !queue
    ) {

        return;
    }


    const now =
        Date.now();


    let changed =
        false;


    for (
        const [
            requestId,
            packet
        ]
        of queue
    ) {


        if (
            Number(
                packet.expiresAt
            ) <= now
        ) {


            queue.delete(
                requestId
            );


            changed =
                true;


            continue;
        }


        emitToNode(
            recipient,
            "internet:connection_request",
            packet
        );
    }


    if (
        queue.size === 0
    ) {


        queuedConnectionRequests.delete(
            recipient
        );


        changed =
            true;
    }


    if (
        changed
    ) {

        await persistDurableState();
    }
}


async function flushConnectionResponses(
    nodeId
) {


    const requester =
        normalizeNodeId(
            nodeId
        );


    const queue =
        queuedConnectionResponses.get(
            requester
        );


    if (
        !queue
    ) {

        return;
    }


    const now =
        Date.now();


    let changed =
        false;


    for (
        const [
            responseId,
            packet
        ]
        of queue
    ) {


        if (
            Number(
                packet.expiresAt
            ) <= now
        ) {


            queue.delete(
                responseId
            );


            changed =
                true;


            continue;
        }


        emitToNode(
            requester,
            "internet:connection_response",
            packet
        );
    }


    if (
        queue.size === 0
    ) {


        queuedConnectionResponses.delete(
            requester
        );


        changed =
            true;
    }


    if (
        changed
    ) {

        await persistDurableState();
    }


    /*
     * Active responses intentionally remain queued until expiry.
     * Android's response processing is idempotent, so reconnect
     * re-delivery is preferable to losing an offline acceptance.
     */
}


/*
 * =============================================================
 * ANTI-PACKET HELPERS
 * =============================================================
 */

function antiPacketMatchesMeshPacket(
    antiPacket,
    meshPacket
) {


    return (
        antiPacket.messageId ===
            meshPacket.packetId &&

        normalizeNodeId(
            antiPacket.sourceNodeId
        ) ===
            normalizeNodeId(
                meshPacket.sourceNodeId
            ) &&

        normalizeNodeId(
            antiPacket.recipientNodeId
        ) ===
            normalizeNodeId(
                meshPacket.destinationNodeId
            )
    );
}


function isAntiPacketActive(
    antiPacket
) {


    return (
        Number(
            antiPacket.expiresAt
        ) >
        Date.now()
    );
}


/*
 * =============================================================
 * PERIODIC CLEANUP
 * =============================================================
 */

setInterval(
    async () => {


        try {


            const changed =
                cleanupExpiredDurableState(
                    Date.now()
                );


            /*
             * Authentication challenges are intentionally ephemeral.
             */
            const now =
                Date.now();


            for (
                const [
                    socketId,
                    challenge
                ]
                of pendingAuthentications
            ) {


                if (
                    challenge.expiresAt <=
                    now
                ) {

                    pendingAuthentications.delete(
                        socketId
                    );
                }
            }


            if (
                changed
            ) {

                await persistDurableState();
            }


        } catch (
            error
        ) {


            console.error(
                "[cleanup] durable cleanup failed",
                error
            );
        }
    },
    CLEANUP_INTERVAL_MS
);


/*
 * Don't keep Node alive solely because of the cleanup timer.
 */
setInterval(
    () => {},
    2 ** 31 - 1
).unref();


/*
 * =============================================================
 * GENERIC HELPERS
 * =============================================================
 */

function normalizeString(
    value
) {


    if (
        typeof value !==
        "string"
    ) {

        return "";
    }


    return value.trim();
}


function normalizeNodeId(
    value
) {


    return normalizeString(
        value
    )
        .toLowerCase();
}


function shortNode(
    nodeId
) {


    return normalizeNodeId(
        nodeId
    )
        .slice(
            0,
            8
        );
}


function valid() {


    return {
        valid: true
    };
}


function invalid(
    reason
) {


    return {
        valid: false,
        reason
    };
}


function successfulAcknowledgement(
    acknowledgement,
    payload = {}
) {


    if (
        typeof acknowledgement ===
        "function"
    ) {

        acknowledgement({
            ok: true,
            ...payload
        });
    }
}


function failAcknowledgement(
    socket,
    acknowledgement,
    error
) {


    if (
        typeof acknowledgement ===
        "function"
    ) {

        acknowledgement({
            ok: false,
            error
        });
    }


    socket.emit(
        "internet:error",
        {
            error
        }
    );
}


/*
 * =============================================================
 * START SERVER
 * =============================================================
 */

await initializeDurableState();


httpServer.listen(
    PORT,
    "0.0.0.0",
    () => {


        console.log("");
        console.log(
            "=========================================="
        );

        console.log(
            " Plexus Internet Transport"
        );

        console.log(
            "=========================================="
        );

        console.log(
            `HTTP + Socket.IO : http://0.0.0.0:${PORT}`
        );

        console.log(
            `Health           : http://localhost:${PORT}/health`
        );

        console.log(
            `Persistence      : ${persistenceMode}`
        );

        console.log(
            "Encryption       : client-side E2E"
        );

        console.log(
            "Message plaintext: NEVER handled here"
        );

        console.log(
            "=========================================="
        );

        console.log("");
    }
);


let shuttingDown =
    false;


async function shutdown(
    signal
) {


    if (
        shuttingDown
    ) {

        return;
    }


    shuttingDown =
        true;


    console.log(
        `[shutdown] ${signal}`
    );


    try {


        await persistDurableState();


        await new Promise(
            resolveClose => {


                httpServer.close(
                    () => resolveClose()
                );
            }
        );


        if (
            redisClient &&
            redisClient.isOpen
        ) {

            await redisClient
                .quit();
        }


        process.exit(
            0
        );


    } catch (
        error
    ) {


        console.error(
            "[shutdown] failed",
            error
        );


        process.exit(
            1
        );
    }
}


process.on(
    "SIGINT",
    () => {


        void shutdown(
            "SIGINT"
        );
    }
);


process.on(
    "SIGTERM",
    () => {


        void shutdown(
            "SIGTERM"
        );
    }
);
