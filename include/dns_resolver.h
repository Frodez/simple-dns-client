#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include "dns_cache_manager.h"
#include "dns_msg.h"
#include "dns_util.h"

#include <asio.hpp>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <vector>

namespace dns {

typedef std::function<void(result, std::string, std::vector<std::string>)> callback_type;

template <class P>
concept has_post_no_bind = requires(P&& p, callback_type&& callback,
    result&& res, std::string&& resolve, std::vector<std::string>&& vec)
{
    p.post(callback, res, resolve, vec);
};

template <class P>
concept has_post_bind = requires(P&& p, callback_type&& callback,
    result&& res, std::string&& resolve, std::vector<std::string>&& vec)
{
    p.post(std::bind(callback, res, resolve, vec));
};

template <class P>
concept has_post = has_post_no_bind<P> || has_post_bind<P>;

template <class P>
concept has_commit_no_bind = requires(P&& p, callback_type&& callback,
    result&& res, std::string&& resolve, std::vector<std::string>&& vec)
{
    p.commit(callback, res, resolve, vec);
};

template <class P>
concept has_commit_bind = requires(P&& p, callback_type&& callback,
    result&& res, std::string&& resolve, std::vector<std::string>&& vec)
{
    p.commit(std::bind(callback, res, resolve, vec));
};

template <class P>
concept has_commit = has_commit_no_bind<P> || has_commit_bind<P>;

template <class P>
concept valid_thread_pool = std::is_destructible_v<P> &&(has_post<P> != has_commit<P>);

template <class P>
requires valid_thread_pool<P>
class resolver {
private:
    std::shared_ptr<asio::io_context> context;
    asio::ip::udp::socket socket;
    asio::ip::udp::endpoint endpoint;
    std::chrono::milliseconds retry_interval;
    uint8_t retry_times;
    dns_cache_manager cache;
    std::default_random_engine random_engine;
    std::uniform_int_distribution<uint16_t> distribution;
    std::mutex random_mutex;
    std::shared_ptr<P> pool;

    void post(callback_type callback, result result, std::string resolve, std::vector<std::string> vec)
    {
        if constexpr (has_post<P>) {
            if constexpr (has_post_bind<P>) {
                pool->post(std::bind(callback, result, resolve, vec));
            } else {
                pool->post(callback, result, resolve, vec);
            }
        } else {
            if constexpr (has_commit_bind<P>) {
                pool->commit(std::bind(callback, result, resolve, vec));
            } else {
                pool->commit(callback, result, resolve, vec);
            }
        }
    }

    static std::string to_ipv4_query(const std::string& addr)
    {
        std::array<unsigned char, 4> bytes = asio::ip::make_address_v4(addr).to_bytes();
        std::string query { uint8_to_string(bytes[3]) };
        query.push_back('.');
        query.append(uint8_to_string(bytes[2]));
        query.push_back('.');
        query.append(uint8_to_string(bytes[1]));
        query.push_back('.');
        query.append(uint8_to_string(bytes[0]));
        query.push_back('.');
        query.append("in-addr.arpa"); //affix
        return query;
    }

    static std::string to_ipv6_query(const std::string& addr)
    {
        std::array<unsigned char, 16> bytes = asio::ip::make_address_v6(addr).to_bytes();
        std::string query {};
        for (int i = 15; i != 0; i--) {
            auto& byte = bytes[i];
            uint8_t low = byte & 0x0f;
            query.push_back(uint4_to_char(low));
            query.push_back('.');
            uint8_t high = (byte >> 4) & 0x0f;
            query.push_back(uint4_to_char(high));
            query.push_back('.');
        }
        query.append("ip6.arpa"); //affix
        return query;
    }

    uint16_t get_id()
    {
        std::unique_lock<std::mutex> lock(random_mutex);
        return distribution(random_engine);
    }

    void send_domain(const std::string& query)
    {
        auto [buf, len] = dns_msg::from_domain(query, get_id())->to_packet();
        socket.async_send_to(asio::buffer(buf.get(), len), endpoint,
            [](const asio::error_code& ec, size_t send_len) {});
    }

    void send_ipaddr(const std::string& query)
    {
        auto [buf, len] = dns_msg::from_ipaddr(query, get_id())->to_packet();
        socket.async_send_to(asio::buffer(buf.get(), len), endpoint,
            [](const asio::error_code& ec, size_t send_len) {});
    }

    void receive()
    {
        std::shared_ptr<uint8_t[]> buffer { new uint8_t[512] };
        socket.async_receive_from(asio::buffer(buffer.get(), 512), endpoint,
            [this, buffer](const asio::error_code& ec, size_t receive_len) {
                context->post(std::bind(&resolver::receive, this));
                cache.refresh(dns_msg::from_packet({ buffer, receive_len }));
            });
    }

    void handle_domain(
        std::string domain,
        callback_type callback,
        std::shared_ptr<asio::steady_timer> timer,
        uint8_t left_times)
    {
        auto res = cache.get(domain);
        if (res.has_value()) {
            if (timer) {
                timer->cancel();
            }
            // do callback in the thread pool.
            post(callback, result::ok(), domain, std::move(res.value()));
        } else if (left_times == 0) {
            if (timer) {
                timer->cancel();
            }
            // do callback in the thread pool.
            post(callback, result::error("Timeout"), domain, std::vector<std::string> {});
        } else {
            send_domain(domain);
            if (!timer) {
                timer.reset(new asio::steady_timer { *context });
            }
            timer->expires_from_now(retry_interval);
            timer->async_wait(std::bind(&resolver::handle_domain, this, domain, callback, timer, left_times - 1));
        }
    }

    void handle_ipv4_addr(
        std::string addr,
        callback_type callback,
        std::shared_ptr<asio::steady_timer> timer,
        uint8_t left_times)
    {
        auto query = to_ipv4_query(addr);
        auto res = cache.get(query);
        if (res.has_value()) {
            if (timer) {
                timer->cancel();
            }
            // do callback in the thread pool.
            post(callback, result::ok(), addr, std::move(res.value()));
        } else if (left_times == 0) {
            if (timer) {
                timer->cancel();
            }
            // do callback in the thread pool.
            post(callback, result::error("Timeout"), addr, std::vector<std::string> {});
        } else {
            send_ipaddr(query);
            if (!timer) {
                timer.reset(new asio::steady_timer { *context });
            }
            timer->expires_from_now(retry_interval);
            timer->async_wait(std::bind(&resolver::handle_ipv4_addr, this, addr, callback, timer, left_times - 1));
        }
    }

    void handle_ipv6_addr(
        std::string addr,
        callback_type callback,
        std::shared_ptr<asio::steady_timer> timer,
        uint8_t left_times)
    {
        auto query = to_ipv6_query(addr);
        auto res = cache.get(query);
        if (res.has_value()) {
            if (timer) {
                timer->cancel();
            }
            // do callback in the thread pool.
            post(callback, result::ok(), addr, std::move(res.value()));
        } else if (left_times == 0) {
            if (timer) {
                timer->cancel();
            }
            // do callback in the thread pool.
            post(callback, result::error("Timeout"), addr, std::vector<std::string> {});
        } else {
            send_ipaddr(query);
            if (!timer) {
                timer.reset(new asio::steady_timer { *context });
            }
            timer->expires_from_now(retry_interval);
            timer->async_wait(std::bind(&resolver::handle_ipv6_addr, this, addr, callback, timer, left_times - 1));
        }
    }

public:
    resolver(
        const std::shared_ptr<asio::io_context>& context,
        const asio::ip::address& dns_server,
        std::shared_ptr<P> pool,
        std::chrono::milliseconds retry_interval = std::chrono::milliseconds { 100 },
        uint8_t retry_times = 1)
        : context { context }
        , socket { *context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0) }
        , endpoint { dns_server, DNS_PORT }
        , retry_interval { retry_interval }
        , retry_times { retry_times }
        , cache {}
        , random_engine {}
        , distribution { 0, UINT16_MAX }
        , pool { pool }
    {
        // do receive in the thread which io_context is running.
        context->post(std::bind(&resolver::receive, this));
    }

    resolver(
        const std::shared_ptr<asio::io_context>& context,
        const std::string& dns_server,
        std::shared_ptr<P> pool,
        std::chrono::milliseconds retry_interval = std::chrono::milliseconds { 100 },
        uint8_t retry_times = 1)
        : context { context }
        , socket { *context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0) }
        , endpoint { asio::ip::make_address(dns_server), DNS_PORT }
        , retry_interval { retry_interval }
        , retry_times { retry_times }
        , cache {}
        , random_engine {}
        , distribution { 0, UINT16_MAX }
        , pool { pool }
    {
        // do receive in the thread which io_context is running.
        context->post(std::bind(&resolver::receive, this));
    }
    resolver(
        const std::shared_ptr<asio::io_context>& context,
        std::shared_ptr<P> pool,
        std::chrono::milliseconds retry_interval = std::chrono::milliseconds { 100 },
        uint8_t retry_times = 1)
        : context { context }
        , socket { *context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0) }
        , retry_interval { retry_interval }
        , retry_times { retry_times }
        , cache {}
        , random_engine {}
        , distribution { 0, UINT16_MAX }
        , pool { pool }
    {
        auto servers = get_sys_default_servers();
        if (servers.empty()) {
            throw std::runtime_error { "There is no dns server of the system. "
                                       "You must set an address of dns server." };
        }
        endpoint = asio::ip::udp::endpoint { asio::ip::make_address(servers[0]), DNS_PORT };
        // do receive in the thread which io_context is running.
        context->post(std::bind(&resolver::receive, this));
    }

    ~resolver()
    {
        socket.cancel();
        socket.close();
    }

    void resolve_domain(std::string&& domain, callback_type callback)
    {
        if (!is_valid_domain_name(domain)) {
            // fail through
            post(callback, result::error("Invalid domain"), domain, std::vector<std::string> {});
            return;
        }
        auto res = cache.get(domain);
        if (res.has_value()) {
            post(callback, result::ok(), domain, std::move(res.value()));
            return;
        }
        send_domain(domain);
        if (retry_times == 0) {
            post(callback, result::error("Timeout"), domain, std::vector<std::string> {});
            return;
        }
        // do handle in the thread which io_context is running.
        context->post([this, domain, callback]() {
            std::shared_ptr<asio::steady_timer> timer {};
            handle_domain(domain, callback, timer, retry_times - 1);
        });
    }

    void resolve_ipaddr(std::string&& addr, callback_type callback)
    {
        typedef enum mode {
            ipv4 = 0,
            ipv6 = 1,
            undefined = 2,
        } mode;
        mode m = mode::undefined;
        if (is_valid_ipv4_addr(addr)) {
            m = mode::ipv4;
        } else if (is_valid_ipv6_addr(addr)) {
            m = mode::ipv6;
        }
        if (m == mode::undefined) {
            // fail through
            post(callback, result::error("Invalid domain"), addr, std::vector<std::string> {});
            return;
        }
        auto query = m == mode::ipv4 ? to_ipv4_query(addr) : to_ipv6_query(addr);
        auto res = cache.get(query);
        if (res.has_value()) {
            post(callback, result::ok(), addr, std::move(res.value()));
            return;
        }
        send_ipaddr(query);
        if (retry_times == 0) {
            post(callback, result::error("Timeout"), addr, std::vector<std::string> {});
            return;
        }
        // do handle in the thread which io_context is running.
        if (m == mode::ipv4) {
            context->post([this, addr, callback]() {
                std::shared_ptr<asio::steady_timer> timer {};
                handle_ipv4_addr(addr, callback, timer, retry_times - 1);
            });
        } else {
            context->post([this, addr, callback]() {
                std::shared_ptr<asio::steady_timer> timer {};
                handle_ipv6_addr(addr, callback, timer, retry_times - 1);
            });
        }
    }
};

}

#endif