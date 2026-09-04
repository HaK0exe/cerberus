const apiKey = process.env.WEBHOOK_RELAY_API_KEY;
const password = process.env.DB_PASSWORD;
module.exports = { apiKey, password, service: "webhook-relay" };
