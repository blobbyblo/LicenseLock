#pragma once

#include <cstdint>
#include <cstddef>

namespace Protocol {

	// Frame Types
	// Each frame begins with 1-byte FrameType and 2-byte big-endian length.
	// Each payload is followed by length bytes.
	enum class FrameType : uint8_t {
		// Decryption Type Decision Frames
		Handshake			= 0x01, // Client --> Server | RSA-OAEP
		Data				= 0x02, // Client <-> Server | AES-GCM

		// Payload Type Decision Frames
		// Currently unused, but reserved for future use
		// Alternative method is to parse JSON message contents
		ChallengeRequest	= 0x03, // Client --> Server | Data Frame
		ChallengeResponse	= 0x04, // Client <-- Server | Data Frame
		AuthRequest			= 0x05, // Client --> Server | Data Frame
		AuthResponse		= 0x06, // Client <-- Server | Data Frame
		ModuleRequest		= 0x07, // Client --> Server | Data Frame
		ModuleResponse		= 0x08, // Client <-- Server | Data Frame

		// Error Frames
		Error				= 0xFF  // Client <-> Server | No Encryption
	};

	// Wire Constants
	static constexpr size_t LENGTH_FIELD_SIZE	= 2; // 2-byte big-endian length
	static constexpr size_t HEADER_SIZE			= 1 + LENGTH_FIELD_SIZE; // 1-byte FrameType + 2-byte length

	// AES-GCM Constants
	static constexpr size_t IV_SIZE				= 12; // 96-bit IV
	static constexpr size_t TAG_SIZE			= 16; // 128-bit tag

	// Payload Constants
	static constexpr size_t MAX_PAYLOAD_SIZE	= 0xFFFF; // 2-byte length field

	// Big-endian conversion functions
	inline uint16_t read_be_length(const uint8_t* buff) {
		return (uint16_t(buff[0]) << 8) | uint16_t(buff[1]);
	}
	inline void write_be_length(uint8_t* buff, uint16_t len) {
		buff[0] = uint8_t(len >> 8);
		buff[1] = uint8_t(len & 0xFF);
	}

} // namespace Protocol
