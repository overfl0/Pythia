#pragma once
#include "stdafx.h"

typedef std::queue<std::vector<char>> multipart_t;

class MultipartResponseWriter
{
    multipart_t multipart;
    char *realOutputBuffer;
    char *outputBuffer;
    int outputSize;
    int outputAvailableSize;

    void createNewPage(const char *begin, const char *end);

public:
    MultipartResponseWriter(char *outputBuffer_, int outputSize_);
    void initialize();
    void writeBytes(const char*);
    void finalize();
    multipart_t getMultipart();
};

constexpr int tempBufSize = 10240;
class TestResponseWriter : public MultipartResponseWriter
{
    char tempBuf[tempBufSize];

public:
    TestResponseWriter();
    std::string getResponse();
};
