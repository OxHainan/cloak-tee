#pragma once
namespace crypto
{
struct RecoverableSignature
{
    // Signature consists of 32 byte R, 32 byte S, and recovery id. Some
    // formats concatenate all 3 into 65 bytes. We stick with libsecp256k1
    // and separate 64 bytes of (R, S) from recovery_id.
    static constexpr size_t RS_Size = 64;
    std::array<uint8_t, RS_Size> raw;
    int recovery_id;
    RecoverableSignature() = default;
    RecoverableSignature(const std::vector<uint8_t>& data)
    {
        std::copy(data.begin(), data.end(), raw.begin());
        recovery_id = (int)data[64];
    }

    std::vector<uint8_t> serialise() const
    {
        std::vector<uint8_t> res(65);
        std::copy(raw.begin(), raw.end(), res.begin());
        res[64] = recovery_id;
        return res;
    }
};
}