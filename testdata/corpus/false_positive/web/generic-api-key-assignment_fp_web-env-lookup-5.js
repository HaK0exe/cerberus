const apiKey = process.env.SEARCH_INDEXER_API_KEY;
const password = process.env.DB_PASSWORD;
module.exports = { apiKey, password, service: "search-indexer" };
