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
 * =============================================================
 * DURABLE STATE ENGINE
 * =============================================================
 *
 * To keep this prototype small and make the persistence backend
 * swappable, Plexus serializes only the three durable maps above.
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
        version: 1,
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
        snapshot.version !== 1
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
        `pendingAnti=${countPendingAntiPackets()}`
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


    return changed;
}


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
