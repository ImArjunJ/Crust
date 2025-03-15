#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

void stress_test_leak_thread(int id, int iterations, double leak_probability)
{
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> sizeDist(1, 256);
    std::uniform_int_distribution<int> opDist(0, 1);
    std::uniform_real_distribution<double> leakDist(0.0, 1.0);

    for (int i = 0; i < iterations; i++)
    {
        size_t size = sizeDist(rng);
        int op = opDist(rng);
        bool leak = (leakDist(rng) < leak_probability);

        if (op == 0)
        {
            char* buffer = new char[size];
            memset(buffer, 'A', size);
            if (i % 100 == 0)
            {
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
            if (!leak)
            {
                delete[] buffer;
            }
        }
        else
        {
            char* buffer = (char*) malloc(size);
            if (buffer)
            {
                memset(buffer, 'B', size);
                if (i % 100 == 0)
                {
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                }
                if (!leak)
                {
                    free(buffer);
                }
            }
        }
    }
    std::cout << "Thread " << id << " completed " << iterations << " iterations." << std::endl;
}

int main()
{
    const int num_threads = 10;
    const int iterations = 10000;
    const double leak_probability = 0.20; // 20% chance to leak

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; i++)
    {
        threads.emplace_back(stress_test_leak_thread, i, iterations, leak_probability);
    }
    for (auto& t : threads)
    {
        t.join();
    }
    std::cout << "Stress test with leaks completed." << std::endl;
    return 0;
}
