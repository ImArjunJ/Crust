#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

int main()
{
    std::cout << "Crust Overflow Test Program" << std::endl;
    char* buffer = (char*) malloc(20);

    // Intentionally overflow the allocated memory to trigger redzone corruption.
    strcpy(buffer, "This string is way too long for the allocated buffer!");
    std::cout << buffer << std::endl;
    free(buffer);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
