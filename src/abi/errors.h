#pragma once
#include <fmt/format.h>
#include "iostream"
namespace errors
{
    inline auto make_length_error(const std::string &name, const size_t &want, const size_t &get) {
        return std::logic_error(fmt::format("{} length isn`t match want {} but get {}", name, want, get));
    }
} // namespace errors

