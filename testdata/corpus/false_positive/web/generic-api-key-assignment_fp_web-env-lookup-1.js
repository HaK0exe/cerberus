const apiKey = process.env.BILLING_WORKER_API_KEY;
const password = process.env.DB_PASSWORD;
module.exports = { apiKey, password, service: "billing-worker" };
