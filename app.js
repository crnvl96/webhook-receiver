// Import Express.js
import express from "express";

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

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

// Route for POST requests
app.post("/", async (req, res) => {
    const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19);
    console.log(`\n\nWebhook received ${timestamp}\n`);
    console.log(JSON.stringify(req.body, null, 2));

    try {
        const response = await fetch(
            "https://serena-energia.app.n8n.cloud/webhook-test/2230ea6e-0034-464b-af3b-51ced545ad2d",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(req.body),
            },
        );

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
