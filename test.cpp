#include "include/dns_resolver.h"

#define THREAD_NUM 3

std::shared_ptr<asio::io_context> context;

std::shared_ptr<dns::resolver<asio::io_context>> resolver;

std::vector<std::thread> threads;

void nothing(const dns::result& err, const std::string& domain, const std::vector<std::string>& res)
{
}

void print_one_line(const dns::result& err, const std::string& domain, const std::vector<std::string>& res)
{
    std::cout << "\n";
}

void print(dns::result& err, const std::string& domain, const std::vector<std::string>& res)
{
    if (err.is_ok()) {
        std::cout << "domain: " << domain << std::endl;
        for (const auto& ip : res) {
            std::cout << "ip: " << ip << std::endl;
        }
    } else {
        std::cout << err.message() << std::endl;
    }
}

void handle_close()
{
    std::cout << "The program will quit." << std::endl;
    if (context) {
        context->stop();
    }
    for (auto& thread : threads) {
        thread.join();
    }
    resolver.reset();
    context.reset();
    exit(0);
}

int main(int argc, char const* argv[])
{
    try {
        signal(SIGINT, [](int sig) {
            handle_close();
        });
        auto servers = dns::get_sys_default_servers();
        if (servers.empty()) {
            throw std::runtime_error { "there is no dns server of the system." };
        }
        std::cout << "choose server: " << servers[0] << std::endl;
        context.reset(new asio::io_context(THREAD_NUM));
        resolver.reset(new dns::resolver<asio::io_context>(context, servers[0],
            context));
        for (auto i = 0; i != THREAD_NUM; i++) {
            threads.emplace_back([]() {
                context->run();
            });
        }
        for (auto i = 0; i != 3000; i++) {
            resolver->resolve_domain("www.baidu.com", nothing);
            resolver->resolve_domain("www.sina.com", nothing);
            resolver->resolve_domain("www.google.com", nothing);
        }
        std::this_thread::sleep_for(std::chrono::seconds { 1 });
        handle_close();
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        handle_close();
    }
    return 0;
}