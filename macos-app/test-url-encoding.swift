#!/usr/bin/env swift

import Foundation

// Test URL encoding with different character sets

let pluginName = "mikekelly/exa-gap"

print("Plugin name: \(pluginName)")
print()

// Current (buggy) implementation - using urlPathAllowed
if let encoded1 = pluginName.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) {
    print("Using .urlPathAllowed:")
    print("  Encoded: \(encoded1)")
    print("  DELETE URL: /plugins/\(encoded1)")
    print("  UPDATE URL: /plugins/\(encoded1)/update")
    print()
}

// Correct implementation - using custom character set (like setCredential)
var allowed = CharacterSet.alphanumerics
allowed.insert(charactersIn: "-_.")
if let encoded2 = pluginName.addingPercentEncoding(withAllowedCharacters: allowed) {
    print("Using custom CharacterSet (alphanumerics + '-_.'):")
    print("  Encoded: \(encoded2)")
    print("  DELETE URL: /plugins/\(encoded2)")
    print("  UPDATE URL: /plugins/\(encoded2)/update")
    print()
}

// What the backend expects (from Rust code using urlencoding::encode)
print("What backend expects:")
print("  DELETE URL: /plugins/mikekelly%2Fexa-gap")
print("  UPDATE URL: /plugins/mikekelly%2Fexa-gap/update")
