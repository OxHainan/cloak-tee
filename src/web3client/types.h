#pragma once
#include <ccf/ds/json.h>
#include <eEVM/bigint.h>
#include <nlohmann/json.hpp>
namespace cloak4ccf
{
struct EthereumConfiguration
{
    eevm::Address service;
    eevm::Address state;
};

DECLARE_JSON_TYPE(EthereumConfiguration)
DECLARE_JSON_REQUIRED_FIELDS(EthereumConfiguration, service, state)
} // namespace cloak4ccf