#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

int main()
{
    std::cout << "Crust UAF C++ Test Program" << std::endl;

    char* buffer = (char*) malloc(50);
    strcpy(buffer, "Hello from Crust malloc");
    std::cout << buffer << std::endl;
    free(buffer);
    strcpy(buffer, "UAF error");
    std::this_thread::sleep_for(std::chrono::seconds(3)); // Wait for quarantine to flush. Useful at end of programs.

    return 0;
}
