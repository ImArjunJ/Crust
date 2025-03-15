#include <cstdlib>
#include <cstring>
#include <iostream>

int main()
{
    std::cout << "Crust C++ Test Program" << std::endl;

    int* arr = new int[10];
    for (int i = 0; i < 10; i++)
    {
        arr[i] = i;
    }
    std::cout << "Array values: ";
    for (int i = 0; i < 10; i++)
    {
        std::cout << arr[i] << " ";
    }
    std::cout << std::endl;
    delete[] arr;

    char* buffer = (char*) malloc(50);
    strcpy(buffer, "Hello from Crust malloc");
    std::cout << buffer << std::endl;
    free(buffer);

    return 0;
}
