#include "CryptoUtils.h"
#include "Util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdexcept>

namespace CryptoUtils {

    static EVP_PKEY* load_private_key(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) throw std::runtime_error("Failed to load private key");
        return pkey;
    }

    static EVP_PKEY* load_public_key(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) throw std::runtime_error("Failed to load public key");
        return pkey;
    }

    std::vector<uint8_t> CryptoUtils::rsa_pss_sign(
        const std::string& priv_key_pem,
        const uint8_t* data, size_t len)
    {
        EVP_PKEY* pkey = load_private_key(priv_key_pem);
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey))
            throw std::runtime_error("PSS SignInit failed");
        EVP_PKEY_CTX* pctx = NULL;
        EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, pkey);
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);

        // determine signature length
        size_t siglen;
        EVP_DigestSign(ctx, NULL, &siglen, data, len);
        std::vector<uint8_t> sig(siglen);
        if (!EVP_DigestSign(ctx, sig.data(), &siglen, data, len))
            throw std::runtime_error("PSS Sign failed");
        sig.resize(siglen);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return sig;
    }

    bool CryptoUtils::rsa_pss_verify(
        const std::string& pub_key_pem,
        const uint8_t* data, size_t len,
        const uint8_t* sig, size_t sig_len)
    {
        EVP_PKEY* pkey = load_public_key(pub_key_pem);
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = NULL;
        EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey);
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);

        int rc = EVP_DigestVerify(ctx, sig, sig_len, data, len);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return (rc == 1);
    }

    // Helpers
    static void throwSSLError(const char* where) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof buf);
        throw std::runtime_error(std::string(where) + ": " + buf);
    }

    // Encrypt with RSA-OAEP via EVP_PKEY
    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem)
    {
        // 1) Load public key
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) throwSSLError("PEM_read_bio_PUBKEY");

        // 2) Create context & init
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_free(pkey);
        if (!ctx) throwSSLError("EVP_PKEY_CTX_new");
        if (EVP_PKEY_encrypt_init(ctx) <= 0) throwSSLError("EVP_PKEY_encrypt_init");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throwSSLError("EVP_PKEY_CTX_set_rsa_padding");

        // 3) Determine buffer length
        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_encrypt (determine length)");

        std::vector<uint8_t> out(outlen);

        // 4) Perform encryption
        if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_encrypt");
        out.resize(outlen);

        EVP_PKEY_CTX_free(ctx);
        return out;
    }

    // Decrypt with RSA-OAEP via EVP_PKEY
    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem)
    {
        // 1) Load private key
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) throwSSLError("PEM_read_bio_PrivateKey");

        // 2) Create context & init
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_free(pkey);
        if (!ctx) throwSSLError("EVP_PKEY_CTX_new");
        if (EVP_PKEY_decrypt_init(ctx) <= 0) throwSSLError("EVP_PKEY_decrypt_init");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throwSSLError("EVP_PKEY_CTX_set_rsa_padding");

        // 3) Determine buffer length
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_decrypt (determine length)");

        std::vector<uint8_t> out(outlen);

        // 4) Perform decryption
        if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_decrypt");
        out.resize(outlen);

        EVP_PKEY_CTX_free(ctx);
        return out;
    }

    // AES-256-GCM encryption
    bool CryptoUtils::aes_encrypt(const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* pt, size_t pt_len,
        uint8_t* ct,
        uint8_t* tag)
    {
        if (key_len != 32) throw std::runtime_error("AES key must be 32 bytes");
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw std::runtime_error("EVP_EncryptInit_ex failed");

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr))
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

        if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv))
            throw std::runtime_error("EVP_EncryptInit_ex(key/iv) failed");

        int len = 0;
        if (1 != EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len))
            throw std::runtime_error("EVP_EncryptUpdate failed");

        int outl = 0;
        if (1 != EVP_EncryptFinal_ex(ctx, ct + len, &outl))
            throw std::runtime_error("EVP_EncryptFinal_ex failed");

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
            throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    // AES-256-GCM decryption
    bool CryptoUtils::aes_decrypt(const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* ct, size_t ct_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* pt)
    {
        if (key_len != 32) throw std::runtime_error("AES key must be 32 bytes");
        if (tag_len != 16) throw std::runtime_error("GCM tag must be 16 bytes");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw std::runtime_error("EVP_DecryptInit_ex failed");

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr))
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

        if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv))
            throw std::runtime_error("EVP_DecryptInit_ex(key/iv) failed");

        int len = 0;
        if (1 != EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len))
            throw std::runtime_error("EVP_DecryptUpdate failed");

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
            (void*)tag))
            throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");

        int outl = 0;
        int ret = EVP_DecryptFinal_ex(ctx, pt + len, &outl);
        EVP_CIPHER_CTX_free(ctx);
        return (ret == 1);
    }

} // namespace CryptoUtils
