// Import Express.js
import express from "express";
import {
    decryptRequest,
    encryptResponse,
    FlowEndpointException,
} from "./encryption.js";

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const privateKey = process.env.PRIVATE_KEY;
const n8nWebhookUrl =
    process.env.N8N_WEBHOOK_URL ||
    "https://serena-energia.app.n8n.cloud/webhook-test/2230ea6e-0034-464b-af3b-51ced545ad2d";

// Route for GET requests
app.get("/", (req, res) => {
    const {
        "hub.mode": mode,
        "hub.challenge": challenge,
        "hub.verify_token": token,
    } = req.query;

    if (mode === "subscribe" && token === verifyToken) {
        console.log("WEBHOOK VERIFIED");
        res.status(200).send(challenge);
    } else {
        res.status(403).end();
    }
});

// Detect if the request is an encrypted WhatsApp Flow endpoint payload
const isEncryptedFlowRequest = (body) =>
    body &&
    typeof body.encrypted_flow_data === "string" &&
    typeof body.encrypted_aes_key === "string" &&
    typeof body.initial_vector === "string";

// Route for POST requests
app.post("/", async (req, res) => {
    const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19);
    console.log(`\n\nWebhook received ${timestamp}\n`);

    // Encrypted WhatsApp Flow endpoint (data exchange / health check)
    if (isEncryptedFlowRequest(req.body)) {
        if (!privateKey) {
            console.error("PRIVATE_KEY not set; cannot decrypt Flow request");
            return res.status(500).send("Server misconfiguration: PRIVATE_KEY missing");
        }

        let decryptedBody;
        let aesKeyBuffer;
        let initialVectorBuffer;

        try {
            const decrypted = decryptRequest(req.body, privateKey, undefined);
            decryptedBody = decrypted.decryptedBody;
            aesKeyBuffer = decrypted.aesKeyBuffer;
            initialVectorBuffer = decrypted.initialVectorBuffer;
        } catch (err) {
            if (err instanceof FlowEndpointException) {
                console.error("Flow decryption failed:", err.message);
                return res.status(err.statusCode).end();
            }
            console.error("Error decrypting Flow request:", err);
            return res.status(421).end();
        }

        console.log("Decrypted Flow payload:", JSON.stringify(decryptedBody, null, 2));

        // Health check (ping): respond with encrypted { data: { status: "active" } }
        if (decryptedBody.action === "ping") {
            const healthResponse = { data: { status: "active" } };
            const encrypted = encryptResponse(
                healthResponse,
                aesKeyBuffer,
                initialVectorBuffer,
            );
            return res.status(200).type("text/plain").send(encrypted);
        }

        // Data exchange / INIT / BACK: forward decrypted payload to n8n, encrypt response
        try {
            const n8nResponse = await fetch(n8nWebhookUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(decryptedBody),
            });

            if (!n8nResponse.ok) {
                console.error(`n8n returned ${n8nResponse.status}`);
                return res.status(500).end();
            }

            let responsePayload;
            try {
                responsePayload = await n8nResponse.json();
            } catch {
                console.error("n8n response is not valid JSON");
                return res.status(500).end();
            }

            const encrypted = encryptResponse(
                responsePayload,
                aesKeyBuffer,
                initialVectorBuffer,
            );
            console.log(`Flow forwarded to n8n: ${n8nResponse.status}`);
            return res.status(200).type("text/plain").send(encrypted);
        } catch (error) {
            console.error("Error calling n8n for Flow:", error.message);
            return res.status(500).end();
        }
    }

    // Plain webhook (e.g. WhatsApp webhooks without Flow encryption)
    console.log(JSON.stringify(req.body, null, 2));
    try {
        const response = await fetch(n8nWebhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(req.body),
        });
        console.log(`Forwarded to n8n: ${response.status}`);
    } catch (error) {
        console.error("Error forwarding webhook:", error.message);
    }
    res.status(200).end();
});

// Start the server
app.listen(port, () => {
    console.log(`\nListening on port ${port}\n`);
});
