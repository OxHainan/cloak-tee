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
#include "ccf/ds/logger.h"

namespace cloak4ccf
{
    struct TeePrepare
    {
        std::string manager;
        std::string cloakServiceContract;
    };

    DECLARE_JSON_TYPE(TeePrepare)
    DECLARE_JSON_REQUIRED_FIELDS(TeePrepare, manager, cloakServiceContract)

    struct SyncStates
    {
        std::string data;
        std::string tx_hash;
    };

    DECLARE_JSON_TYPE(SyncStates)
    DECLARE_JSON_REQUIRED_FIELDS(SyncStates, data, tx_hash)

    struct SyncReport
    {
        std::string id;
        std::string result;
    };

    DECLARE_JSON_TYPE(SyncReport)
    DECLARE_JSON_REQUIRED_FIELDS(SyncReport, id, result)

    struct SyncPropose
    {
        std::string id;
        bool success;
    };

    DECLARE_JSON_TYPE(SyncPropose)
    DECLARE_JSON_REQUIRED_FIELDS(SyncPropose, id, success)

    struct SyncKeys
    {
        std::string tx_hash;
        std::string data;
    };

    DECLARE_JSON_TYPE(SyncKeys)
    DECLARE_JSON_REQUIRED_FIELDS(SyncKeys, data, tx_hash)

} // namespace cloak4ccf
