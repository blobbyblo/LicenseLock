#include "Util.h"

#include <random>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#ifdef _WIN32
#include <time.h>
#endif

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

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

    std::string slurp_file(const std::string& path) {
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in) throw std::runtime_error("Unable to open " + path);
        std::string contents;
        in.seekg(0, std::ios::end);
        contents.resize((size_t)in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        return contents;
    }

    void split(const std::string& s, char delim, std::vector<std::string>& out) {
        std::string cur;
        for (char c : s) {
            if (c == delim) {
                if (!cur.empty()) out.push_back(cur);
                cur.clear();
            }
            else {
                cur += c;
            }
        }
        if (!cur.empty()) out.push_back(cur);
    }

    std::string to_base64(const uint8_t* data, size_t len) {
        BIO* b64 = BIO_new(BIO_f_base64()), * bio = BIO_new(BIO_s_mem());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        BIO_write(bio, data, (int)len);
        BIO_flush(bio);
        BUF_MEM* bm;
        BIO_get_mem_ptr(bio, &bm);
        std::string ret(bm->data, bm->length);
        BIO_free_all(bio);
        return ret;
    }

    std::vector<uint8_t> from_base64(const std::string& b64) {
        BIO* b64f = BIO_new(BIO_f_base64()), * bio = BIO_new_mem_buf(b64.data(), (int)b64.size());
        BIO_set_flags(b64f, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64f, bio);
        std::vector<uint8_t> out(b64.size());
        int outlen = BIO_read(bio, out.data(), (int)out.size());
        out.resize(outlen);
        BIO_free_all(bio);
        return out;
    }

    std::string current_utc_rfc3339() {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto secs = time_point_cast<seconds>(now);
        std::time_t tt = system_clock::to_time_t(secs);
        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &tt);
#else
        gmtime_r(&tt, &tm);
#endif
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buf);
    }

} // namespace Util
