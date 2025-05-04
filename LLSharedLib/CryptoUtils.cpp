#include "CryptoUtils.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#include <stdexcept>

namespace CryptoUtils {

    // Helper: throw with latest OpenSSL error
    static void throwSSLError(const char* where) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof buf);
        throw std::runtime_error(std::string(where) + ": " + buf);
    }

    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem)
    {
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
        RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!rsa) throwSSLError("PEM_read_bio_RSA_PUBKEY");

        int rsaSize = RSA_size(rsa);
        std::vector<uint8_t> out(rsaSize);
        int len = RSA_public_encrypt(
            (int)data.size(), data.data(),
            out.data(), rsa,
            RSA_PKCS1_OAEP_PADDING
        );
        RSA_free(rsa);
        if (len < 0) throwSSLError("RSA_public_encrypt");
        out.resize(len);
        return out;
    }

    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem)
    {
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
        RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!rsa) throwSSLError("PEM_read_bio_RSAPrivateKey");

        int rsaSize = RSA_size(rsa);
        std::vector<uint8_t> out(rsaSize);
        int len = RSA_private_decrypt(
            (int)data.size(), data.data(),
            out.data(), rsa,
            RSA_PKCS1_OAEP_PADDING
        );
        RSA_free(rsa);
        if (len < 0) throwSSLError("RSA_private_decrypt");
        out.resize(len);
        return out;
    }

    bool aes_encrypt(const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* pt, size_t pt_len,
        uint8_t* ct,
        uint8_t* tag)
    {
        if (key_len != 32) throw std::runtime_error("AES key must be 32 bytes");
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_EncryptInit_ex"); }

        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_CTRL_GCM_SET_IVLEN"); }

        ret = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_EncryptInit_ex(key/iv)"); }

        int outLen = 0;
        ret = EVP_EncryptUpdate(ctx, ct, &outLen, pt, (int)pt_len);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_EncryptUpdate"); }

        // Finalize (GCM doesn’t produce extra ciphertext)
        ret = EVP_EncryptFinal_ex(ctx, ct + outLen, &outLen);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_EncryptFinal_ex"); }

        // Get 16-byte tag
        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_CTRL_GCM_GET_TAG"); }

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    bool aes_decrypt(const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* ct, size_t ct_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* pt)
    {
        if (key_len != 32) throw std::runtime_error("AES key must be 32 bytes");
        if (tag_len != 16) throw std::runtime_error("GCM tag must be 16 bytes");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        int ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_DecryptInit_ex"); }

        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_CTRL_GCM_SET_IVLEN"); }

        ret = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_DecryptInit_ex(key/iv)"); }

        int outLen = 0;
        ret = EVP_DecryptUpdate(ctx, pt, &outLen, ct, (int)ct_len);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_DecryptUpdate"); }

        // Set expected tag value before finalizing
        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag);
        if (ret != 1) { EVP_CIPHER_CTX_free(ctx); throwSSLError("EVP_CTRL_GCM_SET_TAG"); }

        // Finalize: returns <=0 on tag mismatch
        ret = EVP_DecryptFinal_ex(ctx, pt + outLen, &outLen);
        EVP_CIPHER_CTX_free(ctx);
        return (ret == 1);
    }

} // namespace CryptoUtils
