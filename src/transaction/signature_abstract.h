// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include "tls/key_pair.h"

#include <eEVM/rlp.h>

namespace evm4ccf {
using PointCoord = uint256_t;
struct SignatureAbstract {
 protected:
    SignatureAbstract() {}

 public:
    static constexpr size_t r_fixed_length = 32u;
    uint8_t v;
    PointCoord r;
    PointCoord s;

    SignatureAbstract(uint8_t v_, const PointCoord& r_, const PointCoord& s_) :
        v(v_), r(r_), s(s_) {}

    explicit SignatureAbstract(const tls::RecoverableSignature& sig) {
        v = to_ethereum_recovery_id(sig.recovery_id);
        const auto s_data = sig.raw.begin() + r_fixed_length;
        r = eevm::from_big_endian(sig.raw.data(), r_fixed_length);
        s = eevm::from_big_endian(s_data, r_fixed_length);
    }

    eevm::Address signatureAndVerify(const eevm::KeccakHash& tbs) const {
        return get_address_from_public_key_asn1(getPublicKey(tbs));
    }

    std::vector<uint8_t> getPublicKey(const eevm::KeccakHash& tbs) const {
        tls::RecoverableSignature rs;
        to_recoverable_signature(rs);
        auto pubk = tls::PublicKey_k1Bitcoin::recover_key(rs, {tbs.data(), tbs.size()});
        return public_key_asn1(pubk.get_raw_context());
    }

 private:
    void to_recoverable_signature(tls::RecoverableSignature& sig) const {
        sig.recovery_id = from_ethereum_recovery_id(v);
        const auto s_begin = sig.raw.data() + r_fixed_length;
        eevm::to_big_endian(r, sig.raw.data());
        eevm::to_big_endian(s, s_begin);
    }
};

} // namespace evm4ccf
