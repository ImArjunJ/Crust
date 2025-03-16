#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

void test_overflow()
{
    std::cout << "[Test] Overflow scenario" << std::endl;
    char* buffer = (char*) malloc(20);
    strcpy(buffer, "This string is way too long for the allocated buffer!");
    std::cout << "Buffer contents: " << buffer << std::endl;
    free(buffer);
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void test_double_free()
{
    std::cout << "[Test] Double free scenario" << std::endl;
    char* buffer = (char*) malloc(50);
    strcpy(buffer, "Double free test");
    std::cout << "Buffer contents: " << buffer << std::endl;
    free(buffer);
    // Intentional double free.
    free(buffer);
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void test_invalid_free()
{
    std::cout << "[Test] Invalid free scenario" << std::endl;
    int dummy = 123;
    free(&dummy);
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void test_use_after_free()
{
    std::cout << "[Test] Use-after-free scenario" << std::endl;
    char* buffer = (char*) malloc(30);
    strcpy(buffer, "Use-after-free test");
    std::cout << "Buffer contents: " << buffer << std::endl;
    free(buffer);
    buffer[0] = 'X';
    std::cout << "Modified after free: " << buffer << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void test_stress()
{
    std::cout << "[Test] Stress test scenario" << std::endl;
    const int alloc_count = 1000;
    std::vector<char*> pointers;
    for (int i = 0; i < alloc_count; i++)
    {
        char* buf = (char*) malloc(128);
        pointers.push_back(buf);
    }
    for (int i = 0; i < alloc_count; i += 2)
    {
        free(pointers[i]);
    }
    for (int i = 1; i < alloc_count; i += 2)
    {
        free(pointers[i]);
    }
    std::cout << "Allocated and freed " << alloc_count << " blocks." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void run_test(void (*test_func)(), const char* test_name)
{
    std::cout << "[Running Test] " << test_name << std::endl;
    pid_t pid = fork();
    if (pid < 0)
    {
        std::cerr << "Fork failed for test: " << test_name << std::endl;
        exit(1);
    }
    if (pid == 0)
    {
        test_func();
        exit(0);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
        {
            std::cout << "[Test " << test_name << " exited with status " << WEXITSTATUS(status) << "]" << std::endl;
        }
        else if (WIFSIGNALED(status))
        {
            std::cout << "[Test " << test_name << " terminated by signal " << WTERMSIG(status) << "]" << std::endl;
        }
        std::cout << std::endl;
    }
}

int main()
{
    std::cout << "Crust Test Program\n" << std::endl;

    run_test(test_overflow, "Overflow Scenario");
    run_test(test_double_free, "Double Free Scenario");
    run_test(test_invalid_free, "Invalid Free Scenario");
    run_test(test_use_after_free, "Use-After-Free Scenario");
    run_test(test_stress, "Stress Test Scenario");

    return 0;
}
