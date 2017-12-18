#include "stdafx.h"
#include "ResponseWriter.h"

// Note: outputSize is the size CONTAINING the null terminator
MultipartResponseWriter::MultipartResponseWriter(char *outputBuffer_, int outputSize_):
    outputBuffer(outputBuffer_),
    realOutputBuffer(outputBuffer_),
    outputSize(0),
    outputAvailableSize(outputSize_)
{
}

void MultipartResponseWriter::initialize()
{
}

void MultipartResponseWriter::finalize()
{
    if (multipart.size() > 0)
    {
        multipart.back().resize(outputSize);
    }
    else
    {
        outputBuffer[outputSize] = '\0';
    }
}

void MultipartResponseWriter::createNewPage(const char *begin = nullptr, const char *end = nullptr)
{
    if (begin && end)
    {
        multipart.emplace(begin, end);
    }
    else
    {
        multipart.emplace();
        multipart.back().resize(outputAvailableSize - 1);
    }
}

void MultipartResponseWriter::writeBytes(const char* bytes)
{
    for(auto p = bytes; *p; p++)
    {
        if (outputSize == outputAvailableSize - 1)
        {
            // The page is full, create a new one
            if (multipart.empty())
            {
                // First time wrapping, copy data and create another page
                createNewPage(outputBuffer, &outputBuffer[outputSize]);
            }

            createNewPage();
            outputBuffer = multipart.back().data();
            outputSize = 0;
        }

        outputBuffer[outputSize++] = *p;
    }
}

multipart_t MultipartResponseWriter::getMultipart()
{
    return multipart;
}

// ===================================

TestResponseWriter::TestResponseWriter(): MultipartResponseWriter(tempBuf, tempBufSize)
{
    tempBuf[tempBufSize - 1] = '\0';
}

std::string TestResponseWriter::getResponse()
{
    auto multipartResponse = getMultipart();
    if (multipartResponse.empty())
        return tempBuf;

    std::string retval;
    retval.reserve(tempBufSize * multipartResponse.size() + 1);
    while(!multipartResponse.empty())
    {
        auto &v = multipartResponse.front();
        retval.append(v.data(), v.size());
        multipartResponse.pop();
    }
    return retval;
}
