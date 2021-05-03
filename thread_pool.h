#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <vector>
#include <iostream>

class thread_pool {
public:
    thread_pool(size_t);
    template <class F, class... Args>
    auto post(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    ~thread_pool();

private:
    // need to keep track of threads so we can join them
    std::vector<std::thread> workers;
    // the task queue
    std::queue<std::function<void()>> tasks;

    // synchronization
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

// the constructor just launches some amount of workers
inline thread_pool::thread_pool(size_t threads)
    : stop(false)
{
    for (size_t i = 0; i < threads; ++i)
        workers.push_back(std::thread([this] {
            //std::cout << "pool thread:" << std::this_thread::get_id() << std::endl;
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex);
                    this->condition.wait(lock, [this] {
                        return this->stop || !this->tasks.empty();
                    });
                    if (this->stop && this->tasks.empty()) {
                        return;
                    }
                    task = this->tasks.front();
                    this->tasks.pop();
                }
                task();
            }
        }));
}

// add new work item to the pool
template <class F, class... Args>
auto thread_pool::post(F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type>
{
    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<return_type> res = task->get_future();
    std::unique_lock<std::mutex> lock(queue_mutex);

    // don't allow posting after stopping the pool
    if (stop) {
        throw std::runtime_error("post on stopped thread_pool");
    }

    tasks.push([task]() { (*task)(); });
    condition.notify_one();
    lock.unlock();
    return res;
}

// the destructor joins all threads
inline thread_pool::~thread_pool()
{
    std::unique_lock<std::mutex> lock(queue_mutex);
    stop = true;
    condition.notify_all();
    lock.unlock();
    for (std::thread& worker : workers) {
        worker.join();
    }
}

#endif