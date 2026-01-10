/**
 * AWS S3 Plugin
 *
 * Implements AWS Signature Version 4 signing for S3 requests.
 * Supports both bucket.s3.amazonaws.com and s3.amazonaws.com patterns.
 *
 * Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
 */
var plugin = {
    name: "aws-s3",
    matchPatterns: ["*.s3.amazonaws.com", "s3.amazonaws.com"],
    credentialSchema: ["access_key_id", "secret_access_key", "region"],

    transform: function(request, credentials) {
        // Parse the URL to extract components
        var url = new URL(request.url);
        var host = url.hostname;
        var path = url.pathname || "/";
        var queryString = url.search ? url.search.substring(1) : "";

        // Get current timestamp
        var now = ACP.util.now();
        var amzDate = ACP.util.amzDate(now); // YYYYMMDDTHHMMSSZ
        var dateStamp = amzDate.substring(0, 8); // YYYYMMDD

        // Set required headers
        request.headers["host"] = host;
        request.headers["x-amz-date"] = amzDate;

        // Calculate content hash (SHA256 of body)
        var payloadHash = ACP.crypto.sha256Hex(request.body);
        request.headers["x-amz-content-sha256"] = payloadHash;

        // Create canonical request
        var method = request.method;

        // Canonical headers (sorted, lowercase)
        var canonicalHeaders = "host:" + host + "\n" +
                               "x-amz-content-sha256:" + payloadHash + "\n" +
                               "x-amz-date:" + amzDate + "\n";

        var signedHeaders = "host;x-amz-content-sha256;x-amz-date";

        var canonicalRequest = method + "\n" +
                               path + "\n" +
                               queryString + "\n" +
                               canonicalHeaders + "\n" +
                               signedHeaders + "\n" +
                               payloadHash;

        // Create string to sign
        var algorithm = "AWS4-HMAC-SHA256";
        var credentialScope = dateStamp + "/" + credentials.region + "/s3/aws4_request";
        var canonicalRequestHash = ACP.crypto.sha256Hex(canonicalRequest);

        var stringToSign = algorithm + "\n" +
                           amzDate + "\n" +
                           credentialScope + "\n" +
                           canonicalRequestHash;

        // Calculate signature using AWS Signature v4 key derivation
        var kDate = ACP.crypto.hmac("AWS4" + credentials.secret_access_key, dateStamp);
        var kRegion = ACP.crypto.hmac(kDate, credentials.region);
        var kService = ACP.crypto.hmac(kRegion, "s3");
        var kSigning = ACP.crypto.hmac(kService, "aws4_request");
        var signature = ACP.crypto.hmac(kSigning, stringToSign, "hex");

        // Build Authorization header
        var authHeader = algorithm + " " +
                         "Credential=" + credentials.access_key_id + "/" + credentialScope + ", " +
                         "SignedHeaders=" + signedHeaders + ", " +
                         "Signature=" + signature;

        request.headers["Authorization"] = authHeader;

        return request;
    }
};
