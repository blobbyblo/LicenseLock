#include "Util.h"

#include <random>
#include <cstdarg>
#include <cstdio>

namespace Util {

	static std::mt19937& rng() {
		static std::random_device rd;
		static std::mt19937 gen(rd());
		return gen;
	}

	std::vector<uint8_t> generate_random_bytes(size_t n) {
		std::uniform_int_distribution<int> dist(0, 255);
		std::vector<uint8_t> buf(n);
		for (size_t i = 0; i < n; ++i) {
			buf[i] = static_cast<uint8_t>(dist(rng()));
		}
		return buf;
	}

	void log(const char* fmt, ...) {
		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}

	std::string to_hex(const std::vector<uint8_t>& data) {
		static const char* hex_chars = "0123456789abcdef";
		std::string s;
		s.reserve(data.size() * 2);
		for (uint8_t byte : data) {
			s.push_back(hex_chars[byte >> 4]);
			s.push_back(hex_chars[byte & 0x0F]);
		}
		return s;
	}

} // namespace Util
