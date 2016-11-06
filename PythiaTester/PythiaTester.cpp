#include <SDKDDKVer.h>
#include <windows.h>
#include <iostream>
#include <chrono>

typedef void (__stdcall *RVExtension_t)(char *output, int outputSize, const char *function);

RVExtension_t RVExtension;

void test()
{
    char output[10*1024];
    const int iterations = 10000;
    const char *command = "['Pythia.ping', 'asd', 'ert', 3]";

    std::cout << "Calling " << iterations << " times: " << command << std::endl;

    // First call to initialize everything (in case it is needed)
    RVExtension(output, sizeof(output), command);

    auto start = std::chrono::system_clock::now();
    for (int i = iterations; i > 0; i--)
    {
        RVExtension(output, sizeof(output), command);
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = end - start;

    std::cout << "Last call output: " << output << std::endl;
    std::cout << "Each function time: " << elapsed.count() / 10000.0 / (double)iterations << "ms" << std::endl;
}

int main()
{
    HINSTANCE hInstLibrary = LoadLibrary(TEXT("Pythia.dll"));

    if (hInstLibrary)
    {
        RVExtension = (RVExtension_t)GetProcAddress(hInstLibrary, "_RVExtension@12");

        if (RVExtension)
        {
            test();
        }
        else
        {
            std::cout << "Could not get RVExtension function." << std::endl;
        }
        FreeLibrary(hInstLibrary);
    }
    else
    {
        std::cout << "Could not open library dll." << std::endl;
    }

    std::cout << "Press enter to continue...";
    std::cin.get();
    return 0;
}

