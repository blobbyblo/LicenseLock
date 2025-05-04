#pragma once

#include <vector>
#include <cstdint>

namespace Util {

	// Returns a vector of 'n' cryptographically secure random bytes
	std::vector<uint8_t> generate_random_bytes(size_t n);

	// Logging helper function
	void log(const char* fmt, ...);

};
