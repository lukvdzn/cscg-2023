#include <iostream>

int main()
{
    int64_t val, pos;
    int64_t* ptr = &val;

    std::cout << "Hello World!\n";

    while (1)
    {
        std::string cmd;
        std::cout << "Do?\n";
        std::cin >> cmd;

        switch (cmd[0])
        {
        case 'w':
            std::cout << "pos: ";
            std::cin >> pos;
            std::cout << "val: ";
            std::cin >> val;
            ptr[pos] = val;
            break;
        case 'r':
            std::cout << "pos: ";
            std::cin >> pos;
            std::cout << ptr[pos] << "\n";
            break;
        default:
            return 0;
        }
    }
}
