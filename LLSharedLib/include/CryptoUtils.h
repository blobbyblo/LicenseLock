#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace CryptoUtils {

    // RSA-OAEP encryption/decryption using the provided PEM key.
    //   data   – plaintext (encrypt) or ciphertext (decrypt)
    //   keyPem – either a PUBLIC-KEY PEM for encrypt or PRIVATE-KEY PEM for decrypt
    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem);
    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem);

    // AES-GCM encryption/decryption (unchanged):
    //   key/iv        – your 32-byte session key + 12-byte IV
    //   pt/ct         – plaintext/ciphertext buffers
    //   tag           – 16-byte GCM tag (out on encrypt, in on decrypt)
    bool aes_encrypt(const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* pt, size_t pt_len,
        uint8_t* ct,
        uint8_t* tag);

    bool aes_decrypt(const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* ct, size_t ct_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* pt);

}
