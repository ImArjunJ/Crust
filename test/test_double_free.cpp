#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

int main()
{
    std::cout << "Crust Double Free Test Program" << std::endl;
    char* buffer = (char*) malloc(50);
    strcpy(buffer, "Testing double free in Crust.");
    std::cout << buffer << std::endl;

    free(buffer);
    // Intentional double free.
    free(buffer);

    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
