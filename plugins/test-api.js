var plugin = {
    name: "test-api",
    matchPatterns: ["api.example.com"],
    credentialSchema: ["api_key"],
    transform: function(request, credentials) {
        request.headers["Authorization"] = "Bearer " + credentials.api_key;
        return request;
    }
};
