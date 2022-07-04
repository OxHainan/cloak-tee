#pragma once
#include "eEVM/bigint.h"
using export_state_func_t = bool (*)(uint256_t, uint256_t, uint256_t*);
inline export_state_func_t export_state;
