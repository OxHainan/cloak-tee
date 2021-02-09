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
    bool check(string &str) {
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
    std::tuple<string, int, bool> result() {
        cout << str << endl;
         if (!paramTypeSimple[str].empty()) 
        return std::make_tuple(paramTypeSimple[str], 0, false);
    smatch match;
    if (regex_match(str, match, regex(patternBytes))) {
        cout <<"erfw"<< match[1] << endl;
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
        }
        catch(const std::exception& e)
        {
            len = 0;
        }
        return std::make_tuple(match[1], len, true);
    }
    throw std::logic_error(fmt::format("{} can`t parsing", str));
    }
    ~Parsing() {};
};



