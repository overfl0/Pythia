#include "stdafx.h"
#include "SQFGenerator.h"

SQFGenerator::SQFGenerator(int minArrayLen_, int maxArrayLen_):
    minArrayLen(minArrayLen_), maxArrayLen(maxArrayLen_)
{
    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    gen = std::mt19937(rd()); //Standard mersenne_twister_engine seeded with rd()
}

std::string SQFGenerator::generateBoolean()
{
    std::uniform_int_distribution<> dis(0, 1);
    if (dis(gen))
        return "True";
    else
        return "False";
}

std::string SQFGenerator::generateInt()
{
    std::uniform_int_distribution<> dis(-1000000, 1000000);  // Larger?
    return std::to_string(dis(gen));
}

std::string SQFGenerator::cutTrailingZeroes(std::string output)
{
    size_t i;
    for (i = output.size() - 1; i; i--)
    {
        if (output[i] != '0')
        {
            break;
        }
    }
    if (output[i] == '.')
    {
        i--;
    }
    if (i != output.size() - 1)
    {
        output.resize(i + 1);
    }
    return output;
}

std::string SQFGenerator::generateFloat()
{
    std::uniform_real_distribution<> dis(1.0, 1000000.0);  // Larger?
    return cutTrailingZeroes(std::to_string(dis(gen)));
}

std::string SQFGenerator::generateString()
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "~!@#$%^&*()_+|-=\\[]{};:\",.<>/?`"
        ;
    std::uniform_int_distribution<> len(0, 100);
    std::uniform_int_distribution<> letter(0, sizeof(alphanum) - 2);
    int stringLength = len(gen);

    std::string output;
    output.resize(stringLength + 2);
    output[0] = '\'';
    for (int i = 1; i <= stringLength; i++)
    {
        output[i] = alphanum[letter(gen)];
    }
    output[stringLength + 1] = '\'';

    return output;
}

std::string SQFGenerator::generateStringEscaped()
{
    // TODO: Add escaped ""
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "~!@#$%^&*()_+|-=\\[]{};:',.<>/?`"
        ;
    std::uniform_int_distribution<> len(0, 100);
    std::uniform_int_distribution<> letter(0, sizeof(alphanum) - 2);
    int stringLength = len(gen);

    std::string output;
    output.resize(stringLength + 2);
    output[0] = '"';
    for (int i = 1; i <= stringLength; i++)
    {
        output[i] = alphanum[letter(gen)];
    }
    output[stringLength + 1] = '"';

    return output;
}

std::string SQFGenerator::generateList(int max_depth)
{
    std::uniform_int_distribution<> len(minArrayLen, maxArrayLen);
    std::uniform_int_distribution<> recursive(0, 5);
    std::uniform_int_distribution<> nonrecursive(1, 5);
    std::uniform_int_distribution<> selection;
    if (max_depth > 0)
        selection = recursive;
    else
        selection = nonrecursive;

    std::string output = "[";
    int listSize = len(gen);
    for (int i = 0; i < listSize; i++)
    {
        if (i)
            output += ",";

        std::string element;
        switch (selection(gen))
        {
        case 0: element = generateList(max_depth - 1); break;
        case 1: element = generateBoolean(); break;
        case 2: element = generateInt(); break;
        case 3: element = generateFloat(); break;
            //case 4: element = generateString(); break;
        case 4: element = generateStringEscaped(); break;
        case 5: element = generateStringEscaped(); break;
        }

        output += element;
    }

    output += "]";

    return output;
}

std::string SQFGenerator::generate(int max_depth)
{
    std::string out(generateList(max_depth));
    return out;
}
