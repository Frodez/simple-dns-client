#ifndef DNS_CACHE_MANAGER_H
#define DNS_CACHE_MANAGER_H

#include "dns_msg.h"

#include <condition_variable>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace dns {

class dns_cache_manager {
private:
    std::unordered_map<std::string, std::vector<std::string>> cache;
    std::mutex m;
    static std::unordered_map<std::string, std::vector<std::string>> parse_dns_msg(std::unique_ptr<dns_msg> msg)
    {
        std::unordered_map<std::string, std::string> cnames {};
        std::unordered_map<std::string, std::vector<std::string>> relations {};
        for (auto& answer : msg->answer) {
            if (answer.rtype == DNS_IPV4_TYPE || answer.rtype == DNS_IPV6_TYPE || answer.rtype == DNS_PTR_TYPE) {
                auto& key = answer.name;
                auto& value = answer.rdata;
                if (relations.find(key) == relations.end()) {
                    relations[key] = std::move(std::vector<std::string> { value });
                } else {
                    relations[key].push_back(value);
                }
            } else if (answer.rtype == DNS_CNAME_TYPE) {
                auto& name = answer.name;
                auto& alias = answer.rdata;
                for (auto& cname : cnames) {
                    if (cname.second == name) {
                        cname.second = alias;
                    }
                }
                cnames[name] = alias;
            }
        }
        for (auto& cname : cnames) {
            auto& name = cname.first;
            auto& alias = cname.second;
            relations[name] = relations[alias];
        }
        return relations;
    }

public:
    std::optional<std::vector<std::string>> get(const std::string& domain)
    {
        std::unique_lock<std::mutex> lock(m);
        auto f = cache.find(domain);
        if (f == cache.end()) {
            return {};
        } else {
            return f->second;
        }
    }
    void refresh(std::unique_ptr<dns_msg> msg)
    {
        if (msg->header.is_ok() || msg->query.empty() || msg->answer.empty()) {
            return;
        }
        auto relations = dns_cache_manager::parse_dns_msg(std::move(msg));
        std::unique_lock<std::mutex> lock(m);
        for (auto& item : relations) {
            cache[item.first] = std::move(item.second);
        }
    }
};

}

#endif