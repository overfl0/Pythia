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
    const char *command = "['pythia.ping', 'asd', 'ert', 3]";

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

void test_coroutines()
{
    char output[10 * 1024];
    const int iterations = 10000;
    const char *command = "['python.coroutines.test_coroutines']";
    char *response = _strdup("['pythia.continue',         , 'tralala something']");
    char number[10];

    int continue_val;

    std::cout << "Calling " << iterations << " times: " << command << std::endl;

    // First call to initialize everything (in case it is needed)
    RVExtension(output, sizeof(output), command);

    auto start = std::chrono::system_clock::now();
    for (int i = iterations; i > 0; i--)
    {
        RVExtension(output, sizeof(output), command);
        while (output[2] == 's')
        {
            continue_val = atoi(output + 5);
            sprintf_s(number, "%6d", continue_val);
            for (int j = 0; j < 6; j++)
            {
                response[20 + j] = number[j];
            }
            RVExtension(output, sizeof(output), response);
        }
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = end - start;

    std::cout << "Last call output: " << output << std::endl;
    std::cout << "Each function time: " << elapsed.count() / 10000.0 / (double)iterations << "ms" << std::endl;
}

#ifdef _WIN64
#define PYTHIA_DLL "Pythia_x64.dll"
#define FUNCNAME "RVExtension"
#else
#define PYTHIA_DLL "Pythia.dll"
#define FUNCNAME "_RVExtension@12"
#endif


int main()
{
    HINSTANCE hInstLibrary = LoadLibrary(TEXT(PYTHIA_DLL));

    if (hInstLibrary)
    {
        RVExtension = (RVExtension_t)GetProcAddress(hInstLibrary, FUNCNAME);

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

