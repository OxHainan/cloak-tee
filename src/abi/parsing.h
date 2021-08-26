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
#include "string"
#include "map"
#include <fmt/format.h>
#include "regex"
using namespace std;
 
static map<string, string> paramTypeSimple = {
    {"address", "address"},
    {"bool", "bool"},
    {"bytes", "bytes"},
    {"string", "string"},
    {"uint", "uint"},
};
static string patternBytes = "^bytes([0-9]*)$";
static string patternMapping = "^mapping\\((.*)\\)$";
static string patternNumber = "^(u?int)([0-9]*)$";
static string patternArray = "^(.*)\\[([0-9]*)\\]$";  
class Parsing
{
 private:
    string str;

 public:
    Parsing() {}
    Parsing(string _str): str(_str) {}

    // bug 未解决 对数组类型检查无效，但同样的表达式在result()却可以
    // 详细调用在 rpc_types_serialization.inl文件第129行
    // 入参变量类型检查
    inline bool check(string &str) {
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

    // 获取匹配的变量名，大小，是否为数组变量
    std::tuple<string, int, bool> result() {
         if (!paramTypeSimple[str].empty()) 
        return std::make_tuple(paramTypeSimple[str], 0, false);
    smatch match;
    if (regex_match(str, match, regex(patternBytes))) {
        size_t len;
        try
        {
            len = stoi(match[1]);
        }
        catch(const std::exception& e)
        {
            len = 0;
        }
        return std::make_tuple("bytes", len, false);
    }
    if (regex_match(str, match, regex(patternNumber))) {       
        
        return std::make_tuple(match[1], stoi(match[2]), false);
    }

    if (regex_match(str, match, regex(patternArray))) {
        size_t len;
        try
        {
            len = stoi(match[2]);
        } catch(const std::exception& e) {
            len = 0;
        }
        return std::make_tuple(match[1], len, true);
    }
    throw std::logic_error(fmt::format("{} can`t parsing", str));
    }
    ~Parsing() {}
};



