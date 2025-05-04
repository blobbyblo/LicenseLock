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

};
