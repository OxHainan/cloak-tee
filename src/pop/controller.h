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
#include "app/rpc/context.h"
#include "ethereum/block_validator.h"
#include "tables.h"
#include "types.h"

namespace Pop {
class Controller {
 public:
    explicit Controller(cloak4ccf::CloakContext& ctx_) :
        ctx(ctx_), m_tables(ctx_.cloakTables.popTables) {}

    static ProposalInfo setup(cloak4ccf::CloakContext& ctx_, const SendSetup& ss) {
        auto con = Controller(ctx_);
        return con.setup(ss);
    }

    ProposalInfo get_proposal(const GetProposal& obj) {
        auto ps = ctx.tx.get_view(m_tables.proposals);
        if (obj.proposalId.has_value()) {
            return ps->get(obj.proposalId.value()).value_or(ProposalInfo{});
        } else if (obj.blockHash.has_value()) {
            auto be = ctx.tx.get_view(m_tables.blockExist);
            auto proposalId = be->get(obj.blockHash.value());
            if (proposalId.has_value()) {
                return ps->get(proposalId.value()).value_or(ProposalInfo{});
            }

            throw std::runtime_error(
                fmt::format("Block hash doesn't setup, get {}", obj.blockHash.value()));
        }

        throw std::invalid_argument("Invalid input proposalId or block hash");
    }

    std::tuple<State, std::string> complete(const SendComplete& sc) {
        auto [ps, be, rs] =
            ctx.tx.get_view(m_tables.proposals, m_tables.blockExist, m_tables.results);
        auto proposalId = be->get(sc.blockHash);
        if (!proposalId.has_value()) {
            throw std::runtime_error("Block doesn't setup");
        }

        auto proposal = ps->get(proposalId.value());
        if (!proposal.has_value()) {
            throw std::runtime_error("Read proposal failed");
        }

        if (proposal->state != State::SETUP) {
            throw std::runtime_error("Proposal doesn't at setup state");
        }

        proposal->completeTime = sc.timestamp;
        std::string resultMessage;

        if (!proposal->validate()) {
            resultMessage = "Validate proposal timestamp failed";
        }

        auto bv = Ethereum::BlocksValidator(sc.body);
        if (!bv.validateBody() &&
            bv.validateTransaction(proposal->blockHash, uint256_t(proposal->createTime))) {
            resultMessage = "Proposal validator failed";
            proposal->state = State::FAILED;
        } else {
            proposal->state = State::COMPLETE;
        }

        CLOAK_DEBUG_FMT("proposal:{}, result: {}", nlohmann::json(proposal).dump(), resultMessage);
        ps->put(proposalId.value(), proposal.value());
        rs->put(proposalId.value(), {resultMessage, bv.to_be_signed()});
        return make_tuple(proposal->state, resultMessage);
    }

 private:
    ProposalInfo setup(const SendSetup& ss) {
        auto [ps, be] = ctx.tx.get_view(m_tables.proposals, m_tables.blockExist);
        if (check_block(ss.blockHash)) {
            throw std::runtime_error("Block has alread setup");
        }

        auto p = ProposalInfo{State::SETUP, ss.timestamp, 0, ss.blockHash};
        ps->put(ss.proposalId, p);
        be->put(ss.blockHash, ss.proposalId);
        return p;
    }

    bool check_block(const BlockHash& hash) const {
        auto be = ctx.tx.get_view(m_tables.blockExist);
        return be->get(hash).has_value();
    }

    cloak4ccf::CloakContext& ctx;
    Tables& m_tables;
};
} // namespace Pop
