#pragma once

class SQFGenerator
{
    std::mt19937 gen;
    int minArrayLen;
    int maxArrayLen;

    std::string generateBoolean();
    std::string generateInt();
    std::string cutTrailingZeroes(std::string output);
    std::string generateFloat();
    std::string generateString();
    std::string generateStringEscaped();
    std::string generateList(int max_depth);

public:
    SQFGenerator(int minArrayLen_, int maxArrayLen_);
    std::string generate(int max_depth);
};
