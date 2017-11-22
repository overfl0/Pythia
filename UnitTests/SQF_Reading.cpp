#include "stdafx.h"
#include "CppUnitTest.h"
#include "CppUnitTestLogger.h"
#include "Python.h"

#include "../src/SQFreader.h"
#include "../src/SQFReader.cpp"  // I don't know why I cannot make VS use pythia.lib :(
#include "../src/ExceptionFetcher.h"
//#include "../src/ExceptionFetcher.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace SQF_Reading_Test
{
    std::string python_str(PyObject *obj)
    {
        PyObject *repr_obj = PyObject_Repr(obj);
        if (repr_obj)
        {
            char *value_utf8 = PyUnicode_AsUTF8(repr_obj);
            if (value_utf8)
            {
                return value_utf8;
            }
            else
            {
                return "Could not convert to unicode";
            }
        }
        else
        {
            return "Could not call repr()";
        }
    }

    void sqf_to_python(const char *sqf, const char *python)
    {
        PyObject *obj = SQFReader::decode(&sqf);
        Assert::IsNotNull(obj);
        std::string output = python_str(obj);
        Assert::AreEqual(python, output.c_str());
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

        TEST_METHOD(SQFBooleanParsing)
        {
            sqf_to_python("True", "True");
            sqf_to_python("tRue", "True");
            sqf_to_python("TrUE", "True");
            sqf_to_python("False", "False");
            sqf_to_python("fAlSe", "False");
            sqf_to_python("FaLsE", "False");
        }

        TEST_METHOD(SQFIntegerParsing)
        {
            sqf_to_python("0", "0");
            sqf_to_python("250", "250");
            sqf_to_python("1000", "1000");
            sqf_to_python("-5", "-5");
        }

        TEST_METHOD(SQFFloatParsing)
        {
            sqf_to_python("0.0", "0.0");
            sqf_to_python("1.5", "1.5");
            sqf_to_python("-1.5", "-1.5");
            sqf_to_python("1234.0", "1234.0");
            sqf_to_python("12345.6", "12345.6");
        }

        TEST_METHOD(SQFListParsing)
        {
            sqf_to_python("[]", "[]");
            sqf_to_python("[True]", "[True]");
            sqf_to_python("[True, False]", "[True, False]");
            sqf_to_python("[[[]]]", "[[[]]]");
            sqf_to_python("[[0, 0], [0, 1], [0, 2]]", "[[0, 0], [0, 1], [0, 2]]");
            sqf_to_python("[[0.25, 'as'], [TRUE, FALSE], [150, -2]]", "[[0.25, 'as'], [True, False], [150, -2]]");
        }

        TEST_METHOD(SQFStringParsing)
        {
            sqf_to_python("''", "''");                                  // '' => ''
            sqf_to_python("'test'", "'test'");
            sqf_to_python("'test\\test'", "'test\\\\test'");            // Ignore \ escaping
            sqf_to_python("'test\ntest'", "'test\\ntest'");             // Newline in string
            sqf_to_python("'test\"\"test'", "'test\"\"test'");          // test"test => test"test (no escaping because of '...')
        }

        TEST_METHOD(SQFStringEscapedParsing)
        {
            sqf_to_python("\"\"", "''");                                // "" => ''
            sqf_to_python("\"test\"\"\"\"test\"", "'test\"\"test'");    // test""""test => test""test
            sqf_to_python("\"test\"\"test\"", "'test\"test'");          // test""test => test"test
            sqf_to_python("\"\"\"test'test\"\"\"", "'\"test\\'test\"'");// ""test'test"" => "test\'test"
        }

        TEST_METHOD(SQFStringUTF)
        {
            sqf_to_python("'\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87'", "'\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87'");
        }

        TEST_METHOD(SQFStrangeWhitespace)
        {
            sqf_to_python("   15   ", "15");
            sqf_to_python(" [ 23  ,   19  ]  ", "[23, 19]");
            sqf_to_python("  [  [  [  ' asd, ert ' ]  ,  False ]  ]", "[[[' asd, ert '], False]]");
            sqf_to_python("[[[' asd, ert '],False]]", "[[[' asd, ert '], False]]");
        }
    };
}
