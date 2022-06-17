#pragma once

#include <ccf/ds/json.h>
#include <host/configuration.h>
#include <web3client/config.h>
namespace host
{
struct CloakHostConfig : CCHostConfig
{
    struct EndPoint
    {
        std::string host = "127.0.0.1";
        uint64_t port = 8545;
        bool operator==(const EndPoint&) const = default;
    };

    EndPoint gateway = {};
};

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CloakHostConfig::EndPoint);
DECLARE_JSON_REQUIRED_FIELDS(CloakHostConfig::EndPoint);
DECLARE_JSON_OPTIONAL_FIELDS(CloakHostConfig::EndPoint, host, port);

DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(CloakHostConfig, CCHostConfig);
DECLARE_JSON_REQUIRED_FIELDS(CloakHostConfig);
DECLARE_JSON_OPTIONAL_FIELDS(CloakHostConfig, gateway);
}