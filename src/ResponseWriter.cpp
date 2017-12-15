#include "stdafx.h"
#include "ResponseWriter.h"

MultipartResponseWriter::MultipartResponseWriter(char *outputBuffer_, int outputSize_):
    outputBuffer(outputBuffer_),
    realOutputBuffer(outputBuffer_),
    outputSize(0),
    outputAvailableSize(outputSize_)
{
}

void MultipartResponseWriter::initialize()
{
    //writeBytes("[\"r\",");
}

void MultipartResponseWriter::finalize()
{
    //writeBytes("]");
}

void MultipartResponseWriter::createNewPage(const char *begin = nullptr, const char *end = nullptr)
{
    if (begin && end)
    {
        multipartVector.emplace_back(begin, end);
    }
    else
    {
        multipartVector.emplace_back();
        multipartVector.back().resize(outputAvailableSize + 1);
        multipartVector.back()[0] = '\0';
    }
}

void MultipartResponseWriter::writeBytes(const char* bytes)
{
    for(auto p = bytes; *p; p++)
    {
        if (outputSize == outputAvailableSize)
        {
            // The page is full, create a new one
            if (multipartVector.size() == 0)
            {
                // First time wrapping, copy data and create another page
                createNewPage(outputBuffer, &outputBuffer[outputSize]);
            }

            createNewPage();
            outputBuffer = multipartVector.back().data();
            outputSize = 0;
        }

        outputBuffer[outputSize++] = *p;
    }
    outputBuffer[outputSize] = '\0'; // Maybe that's not needed?
}

std::vector<std::vector<char>> MultipartResponseWriter::getMultipart()
{
    return multipartVector;
}

// ===================================

TestResponseWriter::TestResponseWriter(): MultipartResponseWriter(tempBuf, tempBufSize)
{
    tempBuf[tempBufSize] = '\0';
}

void TestResponseWriter::initialize()
{
}

void TestResponseWriter::finalize()
{
}

std::string TestResponseWriter::getResponse()
{
    auto multipartResponse = getMultipart();
    if (multipartResponse.size() == 0)
        return tempBuf;

    std::string retval;
    retval.reserve(tempBufSize * multipartResponse.size() + 1);
    for (auto &v : multipartResponse)
    {
        retval.append(v.data(), tempBufSize);
    }
    return retval;
}
