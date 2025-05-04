#pragma once

#include <vector>
#include <cstdint>

#include "Protocol.h"   // from LLSharedLib

class SessionCrypto {

public:
	// Construct with the agreed 32-byte session key
	explicit SessionCrypto(const std::vector<uint8_t>& session_key);

	// Encrypts plaintext into a full Protocol frame:
	//   [Type|LenBE|IV|TAG|CIPHERTEXT]
	bool encrypt_frame(Protocol::FrameType type,
		const std::vector<uint8_t>& plaintext,
		std::vector<uint8_t>& out_frame);

	// Decrypts a full Protocol frame (including IV/TAG) back into plaintext.
	bool decrypt_frame(const std::vector<uint8_t>& in_frame,
		Protocol::FrameType& out_type,
		std::vector<uint8_t>& out_plaintext);

private:
	std::vector<uint8_t> m_session_key;  // 32-byte AES key

}; // class SessionCrypto
