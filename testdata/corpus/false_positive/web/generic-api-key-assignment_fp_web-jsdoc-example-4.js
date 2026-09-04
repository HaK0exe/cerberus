/**
 * Authenticate against the analytics-pipe API.
 *
 * @param {string} apiKey - Example: "your_api_key_here" (see the docs
 *   portal for how to request a real one; never commit a real value).
 * @returns {Promise<Response>}
 */
function authenticate(apiKey) {
  return fetch("/auth", { headers: { "X-Api-Key": apiKey } });
}
