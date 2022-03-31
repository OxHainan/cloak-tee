#pragma once
#include "app/utils.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/recover.h"
#include "crypto/secp256k1/public_key.h"
#include "ethereum/types.h"
#include "fmt/format.h"

#include <eEVM/keccak256.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>

namespace evm4ccf
{
struct ChainIDs
{
    static constexpr size_t pre_eip_155 = 0;
    static constexpr size_t ethereum_mainnet = 1;
    static constexpr size_t expanse_mainnet = 2;
    static constexpr size_t ropsten = 3;
    static constexpr size_t rinkeby = 4;
    static constexpr size_t goerli = 5;
    static constexpr size_t kovan = 42;
    static constexpr size_t geth_private_default = 1337;
};

static size_t current_chain_id = ChainIDs::ethereum_mainnet;

static constexpr size_t pre_155_v_start = 27;
static constexpr size_t post_155_v_start = 35;

inline bool is_pre_eip_155(size_t v)
{
    return v == 27 || v == 28;
}

inline size_t to_ethereum_recovery_id(size_t rec_id)
{
    if (rec_id > 3) {
        throw std::logic_error(fmt::format("ECDSA recovery values should be between 0 and 3, {} is invalid", rec_id));
    }

    if (rec_id > 1) {
        throw std::logic_error(fmt::format(
            "Ethereum only accepts finite curve coordinates, {} represents "
            "an "
            "infinite value",
            rec_id));
    }

    if (current_chain_id == ChainIDs::pre_eip_155) {
        return rec_id + pre_155_v_start;
    }

    return rec_id + current_chain_id * 2 + post_155_v_start;
}

inline size_t from_ethereum_recovery_id(size_t v)
{
    if (is_pre_eip_155(v)) {
        return v - pre_155_v_start;
    }

    constexpr auto min_valid_v = 37u;
    if (v < min_valid_v) {
        throw std::logic_error(fmt::format(
            "Expected v to encode a valid chain ID (must be at least {}), "
            "but is "
            "{}",
            min_valid_v,
            v));
    }

    const size_t rec_id = (v - post_155_v_start) % 2;

    const size_t chain_id = ((v - rec_id) - post_155_v_start) / 2;
    if (chain_id != current_chain_id) {
        LOG_INFO_FMT(
            "Parsed chain ID {} (from v {}), expected to find current chain "
            "ID {}",
            chain_id,
            v,
            current_chain_id);

        throw std::logic_error("Invalid Sender!");
    }

    return rec_id;
}

inline eevm::rlp::ByteString encode_optional_address(const std::optional<eevm::Address>& address)
{
    // The encoding of addresses must be either a fixed-length 20-bytes, or
    // the empty list for the null in contract-creation. If treated as a
    // number, any leading 0s would be stripped.
    eevm::rlp::ByteString encoded;
    if (address.has_value()) {
        constexpr size_t address_length = 20;
        uint8_t address_bytes[address_length] = {};
        intx::be::trunc(address_bytes, *address);
        encoded.insert(encoded.end(), std::begin(address_bytes), std::end(address_bytes));
    }
    return encoded;
}

inline eevm::Address get_address_from_public_key(const std::vector<uint8_t>& pubKey)
{
    if (pubKey[0] != 0x04) {
        throw std::logic_error(fmt::format("Expected ASN.1 key to begin with {}, not {}", 0x04, pubKey[0]));
    }

    const std::vector<uint8_t> bytes(pubKey.begin() + 1, pubKey.end());
    const auto hashed = eevm::Keccak256(bytes);
    return eevm::from_big_endian(hashed.data() + 12, 20u);
}

inline eevm::Address get_address_from_public_key(crypto::KeyPairPtr kp)
{
    auto bytes = kp->public_key_raw();
    return get_address_from_public_key(bytes);
}
struct EthereumTransaction
{
 protected:
    EthereumTransaction() {}

 public:
    size_t nonce;
    uint256_t gas_price;
    uint256_t gas;
    eevm::rlp::ByteString to;
    uint256_t value;
    eevm::rlp::ByteString data;

    EthereumTransaction(size_t nonce_, const Ethereum::MessageCall& tc)
    {
        nonce = nonce_;
        gas_price = tc.gas_price;
        gas = tc.gas;
        to = encode_optional_address(tc.to);
        value = tc.value;
        data = eevm::to_bytes(tc.data);
    }

    explicit EthereumTransaction(const eevm::rlp::ByteString& encoded)
    {
        auto tup =
            eevm::rlp::decode<size_t, uint256_t, uint256_t, eevm::rlp::ByteString, uint256_t, eevm::rlp::ByteString>(
                encoded);

        nonce = std::get<0>(tup);
        gas_price = std::get<1>(tup);
        gas = std::get<2>(tup);
        to = std::get<3>(tup);
        value = std::get<4>(tup);
        data = std::get<5>(tup);
    }

    virtual eevm::rlp::ByteString encode() const
    {
        return eevm::rlp::encode(nonce, gas_price, gas, to, value, data);
    }

    virtual eevm::Keccak256 to_be_signed(bool includeSignature = false) const
    {
        return eevm::Keccak256(encode());
    }

    eevm::Keccak256 to_be_signed_with_chain_id() const
    {
        return eevm::Keccak256(eevm::rlp::encode(nonce, gas_price, gas, to, value, data, current_chain_id, 0, 0));
    }

    virtual void to_transaction_call(Ethereum::MessageCall& tc) const
    {
        tc.gas_price = gas_price;
        tc.gas = gas;
        if (to.empty()) {
            tc.to = std::nullopt;
        } else {
            tc.to = eevm::from_big_endian(to.data(), to.size());
        }
        tc.value = value;
        tc.data = eevm::to_hex_string(data);
    }
};

struct EthereumTransactionWithSignature : public EthereumTransaction
{
    static constexpr size_t r_fixed_length = 32u;
    using PointCoord = uint256_t;
    size_t v;
    PointCoord r;
    PointCoord s;
    EthereumTransactionWithSignature() = default;
    EthereumTransactionWithSignature(
        const EthereumTransaction& tx, size_t v_, const PointCoord& r_, const PointCoord& s_) :
      EthereumTransaction(tx)
    {
        v = v_;
        r = r_;
        s = s_;
    }

    EthereumTransactionWithSignature(const EthereumTransaction& tx, const crypto::RecoverableSignature& sig) :
      EthereumTransaction(tx)
    {
        v = to_ethereum_recovery_id(sig.recovery_id);

        const auto s_data = sig.raw.begin() + r_fixed_length;
        r = eevm::from_big_endian(sig.raw.data(), r_fixed_length);
        s = eevm::from_big_endian(s_data, r_fixed_length);
    }

    explicit EthereumTransactionWithSignature(const eevm::rlp::ByteString& encoded)
    {
        auto tup = eevm::rlp::decode<
            size_t,
            uint256_t,
            uint256_t,
            eevm::rlp::ByteString,
            uint256_t,
            eevm::rlp::ByteString,
            size_t,
            PointCoord,
            PointCoord>(encoded);

        nonce = std::get<0>(tup);
        gas_price = std::get<1>(tup);
        gas = std::get<2>(tup);
        to = std::get<3>(tup);
        value = std::get<4>(tup);
        data = std::get<5>(tup);
        v = std::get<6>(tup);
        r = std::get<7>(tup);
        s = std::get<8>(tup);
    }

    eevm::rlp::ByteString encode() const override
    {
        return eevm::rlp::encode(nonce, gas_price, gas, to, value, data, v, r, s);
    }

    void to_recoverable_signature(crypto::RecoverableSignature& sig) const
    {
        sig.recovery_id = from_ethereum_recovery_id(v);

        const auto s_begin = sig.raw.data() + r_fixed_length;
        eevm::to_big_endian(r, sig.raw.data());
        eevm::to_big_endian(s, s_begin);
    }

    eevm::Keccak256 to_be_signed(bool includeSignature = false) const override
    {
        if (is_pre_eip_155(v)) {
            return EthereumTransaction::to_be_signed(includeSignature);
        }

        // EIP-155 adds (CHAIN_ID, 0, 0) to the data which is hashed, but
        // _only_ for signing/recovering. The canonical transaction hash
        // (produced by encode(), used as transaction ID) is unaffected
        if (includeSignature) {
            return eevm::Keccak256(encode());
        }

        return eevm::Keccak256(eevm::rlp::encode(nonce, gas_price, gas, to, value, data, current_chain_id, 0, 0));
    }

    void to_transaction_call(Ethereum::MessageCall& tc) const override
    {
        EthereumTransaction::to_transaction_call(tc);
        tc.from = get_sender_address();
    }

    eevm::Address get_sender_address() const
    {
        crypto::RecoverableSignature rs;
        to_recoverable_signature(rs);
        const auto tbs = to_be_signed();
        auto pubk = crypto::PublicKey_k1Bitcoin::recover_key(rs, tbs.hash);
        return get_address_from_public_key(pubk.public_key_raw());
    }
};

inline EthereumTransactionWithSignature sign_transaction(
    crypto::KeyPairPtr kp, const EthereumTransaction& tx, bool with_chain_id = false)
{
    eevm::Keccak256 tbs;
    if (with_chain_id) {
        tbs = tx.to_be_signed_with_chain_id();
    } else {
        tbs = tx.to_be_signed();
    }

    const auto sig = kp->sign_hash(tbs.data(), tbs.size());
    crypto::RecoverableSignature re_sig(sig);
    return EthereumTransactionWithSignature(tx, re_sig);
}

inline std::vector<uint8_t> sign_eth_tx(crypto::KeyPairPtr kp, const Ethereum::MessageCall& mc, size_t nonce)
{
    auto ethTx = sign_transaction(kp, EthereumTransaction(nonce, mc), true);
    return ethTx.encode();
}
} // namespace evm4ccf
