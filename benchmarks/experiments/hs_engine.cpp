#include "hs_engine.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <iostream>

HyperscanEngine::HyperscanEngine() : db(nullptr), scratch(nullptr) {}

HyperscanEngine::~HyperscanEngine() {
    if (scratch) {
        hs_free_scratch(scratch);
    }
    if (db) {
        hs_free_database(db);
    }
}

bool HyperscanEngine::load_rules(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open rules file: " << filepath << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        std::istringstream iss(line);
        Rule rule;
        std::string id_str;
        
        if (std::getline(iss, id_str, '\t') &&
            std::getline(iss, rule.target, '\t') &&
            std::getline(iss, rule.regex, '\t')) {
            try {
                rule.id = std::stoul(id_str);
                rules.push_back(rule);
            } catch (const std::exception& e) {
                // Ignore parse errors on specific lines to continue loading
                continue;
            }
        }
    }
    
    std::cout << "Loaded " << rules.size() << " rules from " << filepath << std::endl;
    return true;
}

bool HyperscanEngine::compile() {
    if (rules.empty()) {
        std::cerr << "No rules loaded to compile." << std::endl;
        return false;
    }

    std::vector<const char*> expressions;
    std::vector<unsigned int> flags;
    std::vector<unsigned int> ids;
    
    expressions.reserve(rules.size());
    flags.reserve(rules.size());
    ids.reserve(rules.size());

    for (const auto& rule : rules) {
        expressions.push_back(rule.regex.c_str());
        // Default flags: DOTALL, SINGLEMATCH, CASELESS, ALLOWEMPTY
        // For performance in IDS, SINGLEMATCH is usually ideal
        flags.push_back(HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH | HS_FLAG_CASELESS);
        ids.push_back(rule.id);
    }

    hs_compile_error_t* compile_error = nullptr;
    hs_error_t err = hs_compile_multi(
        expressions.data(),
        flags.data(),
        ids.data(),
        expressions.size(),
        HS_MODE_BLOCK,
        nullptr, // Platform info
        &db,
        &compile_error
    );

    if (err != HS_SUCCESS) {
        std::cerr << "Hyperscan compilation failed: ";
        if (compile_error) {
            std::cerr << compile_error->message << " (Expression " << compile_error->expression << ")" << std::endl;
            hs_free_compile_error(compile_error);
        } else {
            std::cerr << "Unknown error." << std::endl;
        }
        return false;
    }

    err = hs_alloc_scratch(db, &scratch);
    if (err != HS_SUCCESS) {
        std::cerr << "Failed to allocate Hyperscan scratch space." << std::endl;
        hs_free_database(db);
        db = nullptr;
        return false;
    }

    std::cout << "Successfully compiled Hyperscan database and allocated scratch space." << std::endl;
    return true;
}

static int on_match(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* context) {
    (void)from;
    (void)to;
    (void)flags;
    (void)context;
    // std::cout << "Match found! Rule ID: " << id << std::endl;
    return 0; // return 0 to continue scanning, non-zero to halt
}

bool HyperscanEngine::scan(const char* payload, size_t length) const {
    if (!db || !scratch) {
        return false;
    }

    hs_error_t err = hs_scan(db, payload, length, 0, scratch, on_match, nullptr);
    if (err != HS_SUCCESS) {
        std::cerr << "Hyperscan scan failed with error code: " << err << std::endl;
        return false;
    }

    return true;
}

