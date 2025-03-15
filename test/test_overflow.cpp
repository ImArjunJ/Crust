#include <cstdlib>
#include <cstring>
#include <iostream>

int main()
{
    std::cout << "Crust Overflow Test Program" << std::endl;
    char* buffer = (char*) malloc(20);

    // Intentionally overflow the allocated memory to trigger redzone corruption.
    strcpy(buffer, "This string is way too long for the allocated buffer!");

    std::cout << buffer << std::endl;
    free(buffer);
    return 0;
}
