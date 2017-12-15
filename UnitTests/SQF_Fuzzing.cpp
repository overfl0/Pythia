#include "stdafx.h"
#include "CppUnitTest.h"
#include "CppUnitTestLogger.h"
#include "Python.h"
#include "../src/SQFReader.h"
#include "../src/SQFWriter.h"
#include "../src/SQFGenerator.h"
#include "../src/SQFGenerator.cpp"
#include "../src/ResponseWriter.h"
#include "../src/ResponseWriter.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
namespace SQF_Fuzzing_Test
{



    std::string sqf_to_python_to_sqf(const char *sqf)
    {
        PyObject *obj = SQFReader::decode(sqf);
        Assert::IsNotNull(obj);
        TestResponseWriter writer;
        SQFWriter::encode(obj, &writer);
        std::string output = writer.getResponse();
        Py_DECREF(obj);
        return output;
    }

    void sqf_to_python_to_sqf_check(const char *sqf)
    {
        Assert::AreEqual(sqf, sqf_to_python_to_sqf(sqf).c_str());
    }

    TEST_CLASS(SQFGeneratorUnitTest)
    {
    public:
        TEST_CLASS_INITIALIZE(init)
        {
            Py_Initialize();
        }

        TEST_CLASS_CLEANUP(deinit)
        {
            Py_Finalize();
        }

        //=====================================================================

        TEST_METHOD(FuzzingSQFPythonSQF)
        {
            for (int i = 0; i < 1000; i++)
            {
                SQFGenerator builder = SQFGenerator(0, 10);
                std::string s = builder.generate(2);
                try
                {
                    sqf_to_python_to_sqf_check(s.c_str());
                }
                catch (SQFReader::ParseException)
                {
                    Assert::Fail(L"Malformed SQF");
                }
            }
        }
    };
}
