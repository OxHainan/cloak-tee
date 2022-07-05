#pragma once
#include "eEVM/util.h"
#include "iostream"

#include <ccf/crypto/symmetric_key.h>
#include <ds/serialized.h>
#include <eEVM/state.h>
namespace Ethereum
{
class SecretKey
{
 private:
    std::vector<uint8_t> key;

 public:
    SecretKey() : key(crypto::create_entropy()->random(32u)) {}
    SecretKey(const std::vector<uint8_t>& key) : key(key) {}

    std::unique_ptr<crypto::KeyAesGcm> generate_aes_key()
    {
        return crypto::make_key_aes_gcm(key);
    }
};

struct StateCipher : public crypto::GcmCipher
{
    StateCipher() = default;
    StateCipher(size_t size) : crypto::GcmCipher(size) {}
    std::vector<uint8_t> serialise()
    {
        std::vector<uint8_t> serial(64u);
        auto data_ = serial.data();
        auto space = serial.size();

        serialized::write(data_, space, cipher.data(), cipher.size());
        serialized::write(data_, space, hdr.tag, sizeof(hdr.tag));
        serialized::write(data_, space, hdr.iv.data(), hdr.iv.size());
        return serial;
    }

    void deserialise(const std::vector<uint8_t>& serial)
    {
        auto data = serial.data();
        auto size = serial.size();
        cipher = serialized::read(data, size, 32u);
        hdr.deserialise(data, size);
    }
};

template <typename T, typename S>
class StateEncryptorImpl : public eevm::AbstractStateEncryptor
{
 public:
    StateEncryptorImpl(const std::shared_ptr<T>& shared_ctx_) :
      shared_ctx(shared_ctx_)
    {}

    bool encrypt(
        const std::vector<uint8_t>& plain,
        std::vector<uint8_t>& serial) override
    {
        if (plain.size() != 32u) {
            throw std::runtime_error(fmt::format(
                "Specified plain is not of size {}, get {}",
                32u,
                plain.size()));
        }
        S st(plain.size());
        st.hdr.set_random_iv();
        shared_ctx->generate_aes_key()
            ->encrypt(st.hdr.get_iv(), plain, {}, st.cipher, st.hdr.tag);
        serial = st.serialise();
        return true;
    }

    bool decrypt(
        const std::vector<uint8_t>& serial_cipher,
        std::vector<uint8_t>& plain) override
    {
        S st;
        st.deserialise(serial_cipher);
        auto ret =
            shared_ctx->generate_aes_key()
                ->decrypt(st.hdr.get_iv(), st.hdr.tag, st.cipher, {}, plain);
        if (!ret)
            plain.resize(0);
        return ret;
    }

    static eevm::EncryptorPtr make_encryptor(const std::vector<uint8_t>& key)
    {
        return std::make_shared<StateEncryptorImpl<T, S>>(
            std::make_shared<T>(key));
    }

 private:
    std::shared_ptr<T> shared_ctx;
};

using StateEncryptor = StateEncryptorImpl<SecretKey, StateCipher>;

} // namespace Ethereum
