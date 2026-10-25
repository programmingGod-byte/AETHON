#pragma once
#include "aethon/aethon.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>

namespace aethon::dns {

struct TransparentStringHash {
  using is_transparent = void; // no need to convert std::string_view to std::string hash it directly
  size_t operator()(std::string_view sv) const noexcept {
    return std::hash<std::string_view>{}(sv);
  }
};

class DomainBlocklist {
private:
  std::unordered_set<std::string, TransparentStringHash, std::equal_to<>>
      blocked_domains_;

public:
  DomainBlocklist() = default;

    AETHON_ALWAYS_INLINE void add_domain(std::string domain) {
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
    blocked_domains_.insert(std::move(domain));
  }

  size_t load_from_file(const std::string &filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
      return 0;
    }

    std::string line;
    size_t count = 0;
    while (std::getline(file, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ' ||
                               line.back() == '\t')) {
        line.pop_back();
      }
      size_t start = 0;
      while (start < line.size() &&
             (line[start] == ' ' || line[start] == '\t')) {
        ++start;
      }
      if (start >= line.size() || line[start] == '#') {
        continue;
      }
      add_domain(line.substr(start));
      ++count;
    }
    return count;
  }

   AETHON_ALWAYS_INLINE bool is_blocked(std::string_view domain) const noexcept {
        if (AETHON_UNLIKELY(domain.empty() || domain.size() > 255)) {
            return false;
        }
        char buffer[256];
        for (size_t i = 0; i < domain.size(); ++i) {
            buffer[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(domain[i])));
        }
        std::string_view lower_domain(buffer, domain.size());
        if (blocked_domains_.find(lower_domain) != blocked_domains_.end()) {
            return true;
        }
        size_t dot_pos = lower_domain.find('.');
        while (dot_pos != std::string_view::npos) {
            std::string_view parent_domain = lower_domain.substr(dot_pos + 1);
            if (parent_domain.find('.') == std::string_view::npos) {
                break;
            }
            if (blocked_domains_.find(parent_domain) != blocked_domains_.end()) {
                return true;
            }
            dot_pos = lower_domain.find('.', dot_pos + 1);
        }
        return false;
    }

    AETHON_ALWAYS_INLINE bool is_allowed(std::string_view domain) const noexcept {
        if (AETHON_UNLIKELY(domain.empty() || domain.size() > 255)) {
            return false;
        }

        if (blocked_domains_.empty()) {
            return true;
        }

        char buffer[256];
        for (size_t i = 0; i < domain.size(); ++i) {
            buffer[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(domain[i])));
        }
        std::string_view lower_domain(buffer, domain.size());

        if (blocked_domains_.find(lower_domain) != blocked_domains_.end()) {
            return true;
        }

        size_t dot_pos = lower_domain.find('.');
        while (dot_pos != std::string_view::npos) {
            std::string_view parent_domain = lower_domain.substr(dot_pos + 1);
            if (parent_domain.find('.') == std::string_view::npos) {
                break;
            }
            if (blocked_domains_.find(parent_domain) != blocked_domains_.end()) {
                return true;
            }
            dot_pos = lower_domain.find('.', dot_pos + 1);
        }

        return false;
    }


        AETHON_ALWAYS_INLINE size_t size() const noexcept {
        return blocked_domains_.size();
    }
    AETHON_ALWAYS_INLINE bool empty() const noexcept {
        return blocked_domains_.empty();
    }
    AETHON_ALWAYS_INLINE void clear() noexcept {
        blocked_domains_.clear();
    }


};
}; // namespace aethon::dns