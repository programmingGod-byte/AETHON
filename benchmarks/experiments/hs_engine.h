#ifndef HS_ENGINE_H
#define HS_ENGINE_H

#include <hs/hs.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>

struct Rule {
    unsigned int id;
    std::string target;
    std::string regex;
};

class HyperscanEngine {
public:
    HyperscanEngine();
    ~HyperscanEngine();

    // Prevent copying because of raw pointers
    HyperscanEngine(const HyperscanEngine&) = delete;
    HyperscanEngine& operator=(const HyperscanEngine&) = delete;

    bool load_rules(const std::string& filepath);
    bool compile();
    bool scan(const char* payload, size_t length) const;

private:
    std::vector<Rule> rules;
    hs_database_t* db;
    hs_scratch_t* scratch;
};

#endif // HS_ENGINE_H

