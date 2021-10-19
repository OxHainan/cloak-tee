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
#include "iostream"
#include "map"
#include "regex" // NOLINT
#include "string"

#include <fmt/format.h>
using namespace std;

static map<string, string> paramTypeSimple = {{"address", "address"},
                                              {"bool", "bool"},
                                              {"bytes", "bytes"},
                                              {"string", "string"},
                                              {"uint", "uint"},
                                              {"int", "int"}};

static map<string, string> dynamicTypeSimple = {{"bytes", "bytes"}, {"string", "string"}};

inline constexpr auto patternBytes = "^bytes([0-9]*)$";
inline constexpr auto patternMapping = "^mapping\\((.*)\\)$";
inline constexpr auto patternNumber = "^(u?int)([0-9]*)$";
inline constexpr auto patternArray = "^(.*)\\[([0-9]*)\\]$";
class Parsing {
 private:
    string str;

 public:
    Parsing() = delete;
    explicit Parsing(string _str) : str(_str) {}

    inline bool check(string& str) {
        if (!paramTypeSimple[str].empty())
            return true;
        smatch match;
        if (regex_match(str, match, regex(patternBytes)))
            return true;
        if (regex_match(str, match, regex(patternMapping)))
            return true;
        if (regex_match(str, match, regex(patternNumber)))
            return true;
        if (regex_match(str, match, regex(patternArray)))
            return true;

        throw std::logic_error(fmt::format("{} can`t parsing", str));
    }

    static std::pair<bool, std::string> check_dynamic(const string& str) {
        Parsing p(str);
        auto [type, len, boolean] = p.result();
        if (boolean && len == 0) {
            return std::make_pair(boolean, type);
        }

        if (!dynamicTypeSimple[type].empty()) {
            return std::make_pair(true, type);
        }

        if (!paramTypeSimple[type].empty()) {
            return std::make_pair(false, "");
        }
        return std::make_pair(false, type);
    }

    std::tuple<string, int, bool> result() {
        if (!paramTypeSimple[str].empty())
            return std::make_tuple(paramTypeSimple[str], 0, false);
        smatch match;
        if (regex_match(str, match, regex(patternBytes))) {
            size_t len;
            try {
                len = stoi(match[1]);
            } catch (const std::exception& e) {
                len = 0;
            }
            return std::make_tuple("bytes", len, false);
        }
        if (regex_match(str, match, regex(patternNumber))) {
            return std::make_tuple(match[1], stoi(match[2]), false);
        }

        if (regex_match(str, match, regex(patternArray))) {
            size_t len;
            try {
                len = stoi(match[2]);
            } catch (const std::exception& e) {
                len = 0;
            }
            return std::make_tuple(match[1], len, true);
        }

        throw std::logic_error(fmt::format("{} can`t parsing", str));
    }
};
