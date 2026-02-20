import express from "express";
import crypto from "crypto";
import {
    decryptRequest,
    encryptResponse,
    FlowEndpointException,
} from "./encryption.js";

const app = express();

app.use(
    express.json({
        verify: (req, _res, buf, encoding) => {
            req.rawBody = buf?.toString(encoding || "utf8");
        },
    }),
);

const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

const N8N_WEBHOOK_URL =
    "https://serena-energia.app.n8n.cloud/webhook-test/flows-AI_Journey_Calculate_Lead_Discount-endpoint";

async function forwardToN8n(payload) {
    try {
        const res = await fetch(N8N_WEBHOOK_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            console.error(
                "n8n webhook forward failed:",
                res.status,
                await res.text(),
            );
        }
    } catch (err) {
        console.error("n8n webhook forward error:", err.message);
    }
}

// PEM from env often has literal \n instead of newlines; normalize for crypto
function normalizePrivateKey(pem) {
    if (!pem || typeof pem !== "string") return pem;
    return pem.replace(/\\n/g, "\n").trim();
}
const PRIVATE_KEY = normalizePrivateKey(process.env.PRIVATE_KEY);

function isEncryptedFlowRequest(body) {
    return (
        body &&
        typeof body.encrypted_flow_data === "string" &&
        typeof body.encrypted_aes_key === "string" &&
        typeof body.initial_vector === "string"
    );
}

function isRequestSignatureValid(req) {
    if (!APP_SECRET) {
        console.warn(
            "APP_SECRET not set. Set APP_SECRET in env to validate Flow request signatures.",
        );
        return true;
    }
    const header = req.get("x-hub-signature-256");
    if (!header || !header.startsWith("sha256=")) {
        return false;
    }
    const expectedHex = header.replace("sha256=", "");
    const digest = crypto
        .createHmac("sha256", APP_SECRET)
        .update(req.rawBody || "")
        .digest("hex");
    const expectedBuf = Buffer.from(expectedHex, "hex");
    const digestBuf = Buffer.from(digest, "hex");
    if (expectedBuf.length !== digestBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, digestBuf);
}

app.get("/", (req, res) => {
    const {
        "hub.mode": mode,
        "hub.challenge": challenge,
        "hub.verify_token": token,
    } = req.query;

    if (mode === "subscribe" && token === VERIFY_TOKEN) {
        console.log("WEBHOOK VERIFIED");
        res.status(200).send(challenge);
    } else {
        res.status(403).end();
    }
});

app.post("/", async (req, res) => {
    const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19);
    console.log(`\nWebhook received ${timestamp}\n`);

    if (isEncryptedFlowRequest(req.body)) {
        if (!PRIVATE_KEY) {
            console.error("PRIVATE_KEY not set. Cannot decrypt Flow request.");
            return res.status(500).end();
        }

        if (!isRequestSignatureValid(req)) {
            return res.status(432).end();
        }

        let decryptedRequest;
        try {
            decryptedRequest = decryptRequest(
                req.body,
                PRIVATE_KEY,
                PASSPHRASE,
            );
        } catch (err) {
            console.error("Decryption failed:", err.name, err.message);
            if (err instanceof FlowEndpointException) {
                return res.status(err.statusCode).end();
            }
            // Any other decryption error (e.g. wrong key, bad PEM) → 421 so client can refresh key
            return res.status(421).end();
        }

        const { decryptedBody, aesKeyBuffer, initialVectorBuffer } =
            decryptedRequest;
        console.log(
            "Decrypted Flow payload:",
            JSON.stringify(decryptedBody, null, 2),
        );

        forwardToN8n(decryptedBody);

        let responsePayload;
        if (decryptedBody.action === "ping") {
            responsePayload = { data: { status: "active" } };
        } else {
            responsePayload = {
                screen: "SUCCESS",
                data: {
                    extension_message_response: {
                        params: {
                            flow_token: decryptedBody.flow_token || "",
                        },
                    },
                },
            };
        }

        return res
            .status(200)
            .type("text/plain")
            .send(
                encryptResponse(
                    responsePayload,
                    aesKeyBuffer,
                    initialVectorBuffer,
                ),
            );
    }

    console.log(JSON.stringify(req.body, null, 2));
    forwardToN8n(req.body);
    res.status(200).end();
});

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});
