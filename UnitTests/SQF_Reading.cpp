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

    std::string sqf_to_python_string(const char *sqf)
    {
        // Yes, this is leaking memory.
        PyObject *obj = SQFReader::decode(sqf);
        Assert::IsNotNull(obj);
        std::string output = python_str(obj);
        return output;
    }

    void sqf_to_python(const char *sqf, const char *python)
    {
        Assert::AreEqual(python, sqf_to_python_string(sqf).c_str());
    }

    void sqf_raises(const char *sqf, int at_position)
    {
        bool raised = false;
        std::ptrdiff_t error_position = -1;

        try
        {
            sqf_to_python_string(sqf).c_str();
        }
        catch (SQFReader::ParseException& ex)
        {
            raised = true;
            error_position = ex.where_error - sqf;
            //Logger::WriteMessage(ex.what());
        }
        Assert::IsTrue(raised);
        Assert::AreEqual(at_position, (int)error_position);
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
            // ¿ó³æ
            sqf_to_python("'\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87'", "'\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87'");
        }

        TEST_METHOD(SQFStrangeWhitespace)
        {
            sqf_to_python("   15   ", "15");
            sqf_to_python(" [ 23  ,   19  ]  ", "[23, 19]");
            sqf_to_python("  [  [  [  ' asd, ert ' ]  ,  False ]  ]", "[[[' asd, ert '], False]]");
            sqf_to_python("[[[' asd, ert '],False]]", "[[[' asd, ert '], False]]");
        }

        //=====================================================================

        TEST_METHOD(SQFBadSQF)
        {
            sqf_raises("", 0);
            sqf_raises("asd", 0);
        }

        TEST_METHOD(SQFBadSQFTrailingStrings)
        {
            sqf_raises("''asd", 2);
            sqf_raises("\"\"asd", 2);
            sqf_raises("1234abc", 4);
            sqf_raises("12.0abc", 4);
            sqf_raises("Trueabc", 4);
            sqf_raises("TRUEabc", 4);
            sqf_raises("trueabc", 4);
            sqf_raises("Falseabc", 5);
            sqf_raises("FALSEabc", 5);
            sqf_raises("falseabc", 5);
            sqf_raises("[1234abc]", 5);
            sqf_raises("'abc'asd", 5);
        }

        TEST_METHOD(SQFBadSQFNumbers)
        {
            sqf_raises("--15", 0); // The position here is 0 because of some quirks in the parser
            sqf_raises("1.56.34", 0); // The position here is 0 because of some quirks in the parser
            sqf_raises("0x15", 1);
        }

        TEST_METHOD(SQFBadSQFArrays)
        {
            // Arrays not closed correctly
            sqf_raises("[", 1);
            sqf_raises("[15", 3);
            sqf_raises("[15, ['asd']", 12);

            sqf_raises("[15,,56]", 4);
            sqf_raises("]", 0);
        }

        //=====================================================================

        TEST_METHOD(SQFPerformance)
        {
            for (int i = 0; i < 100000; i++)
            {
                PyObject *pyo = SQFReader::decode("[[0.25, 'as'], [TRUE, FALSE], [150, -2]]");
                Py_XDECREF(pyo);
            }
        }
    };
}
