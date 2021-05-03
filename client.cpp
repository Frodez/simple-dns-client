#include "include/dns_resolver.h"
#include "thread_pool.h"

#include <asio.hpp>
#include <fmt/core.h>
#include <memory>

#define THREAD_NUM 3

#define LINE_BUFFER_LEN 1024

std::shared_ptr<asio::io_context> context;

std::shared_ptr<dns::resolver<thread_pool>> resolver;

std::vector<std::thread> threads;

char line[LINE_BUFFER_LEN];

void print(dns::result err, std::string domain, std::vector<std::string> res)
{
    if (err.is_ok()) {
        std::cout << "domain: " << domain << std::endl;
        for (auto ip : res) {
            std::cout << "ip: " << ip << std::endl;
        }
    } else {
        std::cout << err.message() << std::endl;
    }
}

void print_usage(std::string program_name)
{
    std::cout << fmt::format("Usage: {:s} <dns_server_ip>\n", program_name);
}

void print_help()
{
    std::cout << "Please input the domain. If you input 'quit', the program will quit.\
If you input 'clear', the console will be clear. If you input 'usage', the usage will be shown.\n";
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
        std::string program_name { argv[0] };
        if (argc != 2) {
            print_usage(program_name);
            return 0;
        }
        std::string address { argv[1] };
        context.reset(new asio::io_context(THREAD_NUM));
        resolver.reset(new dns::resolver<thread_pool>(context, address,
            std::shared_ptr<thread_pool> { new thread_pool { 1 } }));
        for (auto i = 0; i != THREAD_NUM; i++) {
            threads.push_back(std::thread([]() {
                context->run();
            }));
        }
        print_help();
        typedef enum resolve_mode {
            domain = 0,
            ipaddr = 1,
        } resolve_mode;
        resolve_mode m = resolve_mode::domain;
        while (true) {
            std::cin.getline(line, LINE_BUFFER_LEN);
            std::string in { line };
            if (in == "quit") {
                handle_close();
                break;
            } else if (in == "help") {
                print_help();
            } else if (in == "usage") {
                print_usage(program_name);
            } else if (in == "clear") {
                system("clear");
            } else if (in.starts_with("switch ")) {
                std::string mode = in.substr(7);
                if (mode == "d" || mode == "domain") {
                    m = resolve_mode::domain;
                    std::cout << "switch to domain mode" << std::endl;
                } else if (mode == "ip") {
                    m = resolve_mode::ipaddr;
                    std::cout << "switch to ipaddr mode" << std::endl;
                } else {
                    std::cout << "invalid mode:" << mode << std::endl;
                }
            } else {
                if (m == resolve_mode::domain) {
                    resolver->resolve_domain(std::move(in), print);
                } else if (m == resolve_mode::ipaddr) {
                    resolver->resolve_ipaddr(std::move(in), print);
                } else {
                    std::cout << "wrong mode" << std::endl;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        handle_close();
    }
    return 0;
}