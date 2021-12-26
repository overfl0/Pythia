#ifdef _WIN32
#include <SDKDDKVer.h>
#include <windows.h>
#else
#include <dlfcn.h>
#define __stdcall
#define _strdup strdup
#define sprintf_s sprintf
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <random>
#include "../Pythia/SQFGenerator.h"
#include "../Pythia/SQFGenerator.cpp"
#include "ArmaExtension.h"

#pragma warning( disable : 4996 ) // Disable warning message 4996 (sscanf).

#define ARMA_EXTENSION_BUFFER_SIZE (10*1024)

class ArmaExtensionEx: public ArmaExtension
{
    public:
    using ArmaExtension::ArmaExtension;

    void RVExtensionCheck(char* output, int outputSize, const char* function)
    {
        output[outputSize - 1] = '\0';
        RVExtension(output, outputSize, function);
        if (output[outputSize - 1] != '\0')
        {
            std::cout << "BUFFER OVERFLOW!!!" << std::endl;
            std::cout << "Press enter to continue...";
            std::cin.get();
            exit(1);
        }
    }

    void RVExtensionVersionCheck(char* output, int outputSize)
    {
        output[outputSize - 1] = '\0';
        RVExtensionVersion(output, outputSize);
        if (output[outputSize - 1] != '\0')
        {
            std::cout << "BUFFER OVERFLOW!!!" << std::endl;
            std::cout << "Press enter to continue...";
            std::cin.get();
            exit(1);
        }
    }

    void callVersion()
    {
        char output[32];
        RVExtensionVersionCheck(output, 32);
    }
};



void test(ArmaExtensionEx& extension)
{
    char output[ARMA_EXTENSION_BUFFER_SIZE];
    const int iterations = 10000;
    const char *command = "[\"pythia.ping\", \"asd\", \"ert\", 3]";
    //const char *command = "[\"pythia.test\"]";

    std::cout << "Calling " << iterations << " times: " << command << std::endl;

    // First call to initialize everything (in case it is needed)
    extension.RVExtensionCheck(output, sizeof(output), command);

    auto start = std::chrono::system_clock::now();
    for (int i = iterations; i > 0; i--)
    {
        extension.RVExtensionCheck(output, sizeof(output), command);
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "Last call output: " << output << std::endl;
    std::cout << "Each function time: " << elapsed.count() / 1000.0 / (double)iterations << "ms" << std::endl;
}

std::string createPingRequest(std::string sqf)
{
    return std::string("['pythia.ping', ") + sqf.c_str() + "]";
}

void parseMultipart(const char *output, int &id, int &count)
{
    sscanf(output, "[\"m\",%d,%d]", &id, &count);
}

int compareRegularResponse(const char *response, std::string &expected)
{
    const char responseTemplate[] = "[\"r\",";
    const int payloadOffset = sizeof(responseTemplate) - 1;

    if (strncmp(response, responseTemplate, payloadOffset) == 0)
    {
        if (!strncmp(response + payloadOffset, expected.c_str(), expected.size()))
        {
            if (!strcmp(response + payloadOffset + expected.size(), "]"))
            {
                return 0;
            }
        }

        std::cout << "Expected: " << responseTemplate << expected << "]" << std::endl;
        std::cout << "Got:      " << response << std::endl;
        return 1;
    }

    return -1; // Not a regular response
}

std::string handleMultipart(ArmaExtensionEx& extension, int id, int count)
{
    char output[ARMA_EXTENSION_BUFFER_SIZE];
    std::string multipartRequest = std::string("['pythia.multipart',") + std::to_string(id) + ']';
    std::string fullOutput;

    for (int i = 0; i < count; i++)
    {
        output[0] = '\0';
        extension.RVExtensionCheck(output, sizeof(output), multipartRequest.c_str());
        fullOutput += output;
    }
    //std::cout << fullOutput << std::endl;
    return fullOutput;
}

int test_performance_echo(ArmaExtensionEx& extension, std::string testName, std::string sqf)
{
    int iterations = 100000;
    char output[ARMA_EXTENSION_BUFFER_SIZE];

    std::string request = createPingRequest(sqf);

    auto start = std::chrono::system_clock::now();
    for (int i = 0; i < iterations; i++)
    {
        extension.RVExtensionCheck(output, sizeof(output), request.c_str());
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "Test " << testName << ": " << elapsed.count() / 1000.0 / (double)iterations << "ms" << std::endl;
    return 0;
}

int test_fuzzing_single(ArmaExtensionEx& extension)
{
    char output[ARMA_EXTENSION_BUFFER_SIZE];

    const char multipartTemplate[] = "[\"m\",";
    const int payloadOffset = sizeof(multipartTemplate) - 1;

    SQFGenerator builder = SQFGenerator(0, 100);
    std::string sqf = builder.generate(2);
    std::string request = createPingRequest(sqf);

    extension.RVExtensionCheck(output, sizeof(output), request.c_str());

    // Check for regular response
    int regularResponse = compareRegularResponse(output, sqf);
    if (regularResponse != -1)
        return regularResponse;

    if (strncmp(output, multipartTemplate, payloadOffset) == 0)
    {
        //std::cout << output << std::endl;
        int id, count;
        parseMultipart(output, id, count);
        std::string multipartOutput = handleMultipart(extension, id, count);

        int multipartResponse = compareRegularResponse(multipartOutput.c_str(), sqf);
        if (multipartResponse == -1)
        {
            std::cout << "Got unknown response: " << multipartOutput << std::endl;
        }
        return multipartResponse;
    }
    else
    {
        std::cout << "Got unknown response: " << output << std::endl;
        return 1;
    }
}

void test_fuzzing_multiple(ArmaExtensionEx& extension)
{
    int iterations = 1000;

    auto start = std::chrono::system_clock::now();
    for (int i = 0; i < iterations; i++)
    {
        if (i % 10 == 0)
            std::cout << "Test: " << std::to_string(i) << std::endl;

        if (test_fuzzing_single(extension) != 0)
            return;
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "Tests OK!" << std::endl;
    std::cout << "Each function time: " << elapsed.count() / 1000.0 / (double)iterations << "ms" << std::endl;
}

void test_coroutines(ArmaExtensionEx& extension)
{
    char output[ARMA_EXTENSION_BUFFER_SIZE];
    const int iterations = 10000;
    const char *command = "['python.coroutines.test_coroutines']";
    char *response = _strdup("['pythia.continue',         , 'tralala something']");
    char number[10];

    int continue_val;

    std::cout << "Calling " << iterations << " times: " << command << std::endl;

    // First call to initialize everything (in case it is needed)
    extension.RVExtensionCheck(output, sizeof(output), command);

    auto start = std::chrono::system_clock::now();
    for (int i = iterations; i > 0; i--)
    {
        extension.RVExtensionCheck(output, sizeof(output), command);
        while (output[2] == 's')
        {
            continue_val = atoi(output + 5);
            sprintf_s(number, "%6d", continue_val);
            for (int j = 0; j < 6; j++)
            {
                response[20 + j] = number[j];
            }
            extension.RVExtensionCheck(output, sizeof(output), response);
        }
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "Last call output: " << output << std::endl;
    std::cout << "Each function time: " << elapsed.count() / 1000.0 / (double)iterations << "ms" << std::endl;
}

int waitAndReturn(bool dont_wait, int retval)
{
    if (!dont_wait)
    {
        std::cout << "Press enter to continue...";
        std::cin.get();
    }
    return retval;
}

void defaultTests(ArmaExtensionEx &pythia)
{
    // Warming up
    for (int i = 0; i < 100; i++)
    {
        test_fuzzing_single(pythia);
    }
    // test()
    test_fuzzing_multiple(pythia);
    std::cout << std::endl;
    std::cout << "Note: the tests below do NOT take into account the time Arma deserializes the output!" << std::endl;
    std::cout << "As such, they are only indicative of the extension speed, NOT the in-game speed of these calls!" << std::endl;
    std::cout << std::endl;
    test_performance_echo(pythia, "1 -       Integers (x10)", "[1,2,3,4,5,6,7,8,9,10]");
    test_performance_echo(pythia, "2 -         Floats (x10)", "[1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1]");
    test_performance_echo(pythia, "3 -       Booleans (x10)", "[True,False,True,False,True,False,True,False,True,False]");
    test_performance_echo(pythia, "4 -        Strings (x10)", R"(["abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij"])");
    test_performance_echo(pythia, "5 -  Arrays filled (x10)", "[[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2]]");
    test_performance_echo(pythia, "6 -   Arrays empty (x10)", "[[],[],[],[],[],[],[],[],[],[]]");
    std::cout << std::endl;
    test_performance_echo(pythia, "1 -      Integers (x100)", "[1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7,8,9,10]");
    test_performance_echo(pythia, "2 -        Floats (x100)", "[1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1]");
    test_performance_echo(pythia, "3 -      Booleans (x100)", "[True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False]");
    test_performance_echo(pythia, "4 -       Strings (x100)", R"(["abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij","abcdefghij"])");
    test_performance_echo(pythia, "5 - Arrays filled (x100)", "[[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2],[1,2]]");
    test_performance_echo(pythia, "6 -  Arrays empty (x100)", "[[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]");
}

int main(int argc, char* argv[])
{
    std::filesystem::path path = ".";
    std::string command;
    std::vector<std::string> fakeFiles;
    bool callCommand = false;

    std::ifstream fakeFile;

    // Poor man's commandline parsing
    if (argc > 1)
    {
        callCommand = true;

        int i = 1;
        for (; i < argc; i++)
        {
            if (std::string(argv[i]) == "-o")
            {
                i++;
                if (i >= argc)
                {
                    std::cout << "missing argument" << std::endl;
                    return waitAndReturn(callCommand, 1);
                }

                std::string filename(argv[i]);
                fakeFiles.push_back(filename);
                fakeFile.open(filename);
                //std::cout << "Tester: opening file: " << filename << std::endl;
                if (!fakeFile.is_open())
                {
                    std::cout << "Could not open file: " << filename << std::endl;
                    return waitAndReturn(callCommand, 1);
                }
            }
            else
            {
                break;
            }
        }

        if (i + 1 >= argc)
        {
            std::cout << "missing argument(s)" << std::endl;
            return waitAndReturn(callCommand, 1);
        }

        path = argv[i];
        command = argv[i + 1];
    }

    ArmaExtensionEx pythiaSetPythonPath(path, "PythiaSetPythonPath", true);
    if (!pythiaSetPythonPath)
    {
        std::cout << "Could not open " << pythiaSetPythonPath.fullPath << std::endl;
        return waitAndReturn(callCommand, 1);
    }

    pythiaSetPythonPath.callVersion();
    pythiaSetPythonPath.unload();

    ArmaExtensionEx pythia(path, "Pythia", true);

    if (pythia)
    {
        pythia.callVersion();

        if (pythia.hasRVExtension())
        {
            if (!callCommand)
            {
                defaultTests(pythia);
            }
            else
            {
                char output[ARMA_EXTENSION_BUFFER_SIZE];
                pythia.RVExtensionCheck(output, sizeof(output), command.c_str());
                std::cout << output;
            }
        }
        else
        {
            std::cout << "Could not get RVExtension function." << std::endl;
            return waitAndReturn(callCommand, 1);
        }
        pythia.unload();
     }
    else
    {
        std::cout << "Could not open library: " << pythia.fullPath << std::endl;
        return waitAndReturn(callCommand, 1);
    }

    return waitAndReturn(callCommand, 0);
}
