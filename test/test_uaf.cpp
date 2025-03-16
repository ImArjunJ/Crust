#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

int main()
{
    std::cout << "Crust Use-After-Free Test Program" << std::endl;
    char* buffer = (char*) malloc(30);
    strcpy(buffer, "Use-after-free test.");
    std::cout << buffer << std::endl;

    free(buffer);

    buffer[0] = 'X'; // This should trigger a detection via poisoned memory.
    std::cout << "Modified after free: " << buffer << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
