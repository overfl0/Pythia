#pragma once
#include "stdafx.h"

class ResponseWriter
{
public:
    virtual void writeBytes(const char*) = 0;
    virtual void finalize() = 0;
};

class MultipartResponseWriter: public ResponseWriter
{
    std::vector<std::vector<char>> multipartVector;
    char *realOutputBuffer;
    char *outputBuffer;
    int outputSize;
    int outputAvailableSize;

    void createNewPage(const char *begin, const char *end);

public:
    MultipartResponseWriter(char *outputBuffer_, int outputSize_);
    ~MultipartResponseWriter();
    virtual void writeBytes(const char*);
    virtual void finalize();
    virtual std::vector<std::vector<char>> getMultipart();
};

class TestResponseWriter : public ResponseWriter
{
    std::string output;

public:
    virtual void writeBytes(const char*);
    virtual void finalize();
    std::string getResponse();
};
