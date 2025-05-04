#include "SessionCrypto.h"
#include "CryptoUtils.h"
#include "Util.h"

#include <cstring>  // for memcpy

SessionCrypto::SessionCrypto(const std::vector<uint8_t>& session_key)
	: m_session_key(session_key)
{
}

bool SessionCrypto::encrypt_frame(Protocol::FrameType type,
	const std::vector<uint8_t>& plaintext,
	std::vector<uint8_t>& out_frame)
{
	// 1) generate a fresh IV
	auto iv = Util::generate_random_bytes(Protocol::IV_SIZE);

	// 2) compute lengths
	size_t ct_len = plaintext.size();
	size_t payload_len = Protocol::IV_SIZE + Protocol::TAG_SIZE + ct_len;

	out_frame.resize(Protocol::HEADER_SIZE + payload_len);

	// 3) write frame header
	out_frame[0] = uint8_t(type);
	Protocol::write_be_length(&out_frame[1], uint16_t(payload_len));

	// 4) encrypt into [iv||ct] and write tag
	uint8_t* iv_ptr = out_frame.data() + Protocol::HEADER_SIZE;
	uint8_t* ct_ptr = iv_ptr + Protocol::IV_SIZE;
	uint8_t* tag_ptr = ct_ptr + ct_len;

	if (!CryptoUtils::aes_encrypt(
		m_session_key.data(), m_session_key.size(),
		iv.data(), iv.size(),
		plaintext.data(), plaintext.size(),
		ct_ptr, tag_ptr))
	{
		return false;
	}

	// 5) copy IV
	memcpy(iv_ptr, iv.data(), Protocol::IV_SIZE);
	return true;
}

bool SessionCrypto::decrypt_frame(const std::vector<uint8_t>& in_frame,
	Protocol::FrameType& out_type,
	std::vector<uint8_t>& out_plaintext)
{
	// 1) basic checks
	if (in_frame.size() < Protocol::HEADER_SIZE)
		return false;

	out_type = Protocol::FrameType(in_frame[0]);
	uint16_t payload_len = Protocol::read_be_length(&in_frame[1]);
	if (in_frame.size() != Protocol::HEADER_SIZE + payload_len)
		return false;

	// 2) non-encrypted frames? (we only wrap Data frames)
	if (out_type != Protocol::FrameType::Data) {
		out_plaintext.assign(
			in_frame.begin() + Protocol::HEADER_SIZE,
			in_frame.end());
		return true;
	}

	// 3) extract iv, tag, ct
	const uint8_t* iv_ptr = in_frame.data() + Protocol::HEADER_SIZE;
	const size_t ct_len = payload_len - (Protocol::IV_SIZE + Protocol::TAG_SIZE);
	const uint8_t* ct_ptr = iv_ptr + Protocol::IV_SIZE;
	const uint8_t* tag_ptr = ct_ptr + ct_len;

	out_plaintext.resize(ct_len);
	if (!CryptoUtils::aes_decrypt(
		m_session_key.data(), m_session_key.size(),
		iv_ptr, Protocol::IV_SIZE,
		ct_ptr, ct_len,
		tag_ptr, Protocol::TAG_SIZE,
		out_plaintext.data()))
	{
		return false;
	}

	return true;
}
