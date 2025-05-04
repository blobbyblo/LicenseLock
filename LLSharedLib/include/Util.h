#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace Util {

	// Returns a vector of 'n' cryptographically secure random bytes
	std::vector<uint8_t> generate_random_bytes(size_t n);

	// Logging helper function
	void log(const char* fmt, ...);

	// Converts a byte buffer to a lowercase hex string ("deadbeef...", etc.)
	std::string to_hex(const std::vector<uint8_t>& data);

	// Read entire file into a std::string (slurp_file)
	std::string slurp_file(const std::string& path);

	// Split a string by delimiter
	void split(const std::string& s, char delim, std::vector<std::string>& out);

	// Base64 encode / decode (uses OpenSSL BIO)
	std::string to_base64(const uint8_t* data, size_t len);
	std::vector<uint8_t> from_base64(const std::string& b64);

	// Current UTC timestamp in RFC3339 (e.g. "2025-05-03T15:04:05Z")
	std::string current_utc_rfc3339();
};
