#include <cstdlib>
#include <iostream>

int main()
{
    std::cout << "Crust Invalid Free Test Program" << std::endl;

    int dummy;
    free(&dummy);

    return 0;
}
