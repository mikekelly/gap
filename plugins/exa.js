/**
 * Exa API Plugin
 *
 * Adds Bearer token authentication for api.exa.ai requests.
 * The Exa API uses simple Bearer token authentication.
 *
 * See: https://docs.exa.ai/reference/authentication
 */
var plugin = {
    name: "exa",
    matchPatterns: ["api.exa.ai"],
    credentialSchema: ["api_key"],

    transform: function(request, credentials) {
        // Add Authorization header with Bearer token
        request.headers["Authorization"] = "Bearer " + credentials.api_key;
        return request;
    }
};
