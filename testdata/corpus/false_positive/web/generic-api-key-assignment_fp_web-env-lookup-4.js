const apiKey = process.env.INVENTORY_SYNC_API_KEY;
const password = process.env.DB_PASSWORD;
module.exports = { apiKey, password, service: "inventory-sync" };
