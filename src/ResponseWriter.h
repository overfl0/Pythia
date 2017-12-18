#pragma once
#include "stdafx.h"

class ResponseWriter
{
public:
    virtual void writeBytes(const char*) = 0;
    virtual void initialize() = 0;
    virtual void finalize() = 0;
};

typedef std::queue<std::vector<char>> multipart_t;

class MultipartResponseWriter: public ResponseWriter
{
    multipart_t multipart;
    char *realOutputBuffer;
    char *outputBuffer;
    int outputSize;
    int outputAvailableSize;

    void createNewPage(const char *begin, const char *end);

public:
    MultipartResponseWriter(char *outputBuffer_, int outputSize_);
    virtual void initialize();
    virtual void writeBytes(const char*);
    virtual void finalize();
    virtual multipart_t getMultipart();
};

constexpr int tempBufSize = 10240;
class TestResponseWriter : public MultipartResponseWriter
{
    char tempBuf[tempBufSize];

public:
    TestResponseWriter::TestResponseWriter();
    std::string getResponse();
};
