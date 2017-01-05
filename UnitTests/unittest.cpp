#include "stdafx.h"
#include "CppUnitTest.h"
#include "CppUnitTestLogger.h"
#include "Python.h"

#include "../src/SQFWriter.h"
#include "../src/SQFWriter.cpp"  // I don't know why I cannot make VS use pythia.lib :(
#include "../src/ExceptionFetcher.h"
#include "../src/ExceptionFetcher.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{
    PyObject *python_eval(const char *str)
    {
        // Note: Of course, this function leaks memory.
        // Don't use in production code!
        PyObject* main_module = PyImport_AddModule("__main__");
        PyObject* global_dict = PyModule_GetDict(main_module);
        PyObject* local_dict = PyDict_New();
        PyObject* code = Py_CompileString(str, "pyscript", Py_eval_input);
        PyObject* result = PyEval_EvalCode(code, global_dict, local_dict);

        if (!result)
        {
            std::string error = PyExceptionFetcher().getError();
        }

        return result;
    }

    void python_to_sqf(const char *python, const char *sqf)
    {
        PyObject *obj = python_eval(python);
        std::string output = SQFWriter::encode(obj);
        Assert::AreEqual(sqf, output.c_str());
    }

    TEST_CLASS(SQFGeneratorUnitTest)
    {
        // Note: SQFWriter operates on real, valid PyObject objects, that were
        // created inside python by python code.
        // Hence, the tests test the conversion of valid objects to SQF
        // and there are no "[1, 2" tests (missing closing bracket)

        //Logger::WriteMessage("In StringParsing");
        public:
        TEST_CLASS_INITIALIZE(init)
        {
            Py_Initialize();
        }

        TEST_CLASS_CLEANUP(deinit)
        {
            Py_Finalize();
        }

        TEST_METHOD(NoneParsing)
        {
            python_to_sqf("None", "nil");
        }

        TEST_METHOD(BooleanParsing)
        {

            python_to_sqf("True", "True");
            python_to_sqf("False", "False");
        }

        TEST_METHOD(IntegerParsing)
        {
            python_to_sqf("0", "0");
            python_to_sqf("250", "250");
            python_to_sqf("1000", "1000");
            python_to_sqf("-5", "-5");
        }

        TEST_METHOD(FloatParsing)
        {
            python_to_sqf("0.0", "0");
            python_to_sqf("1.5", "1.5");
            python_to_sqf("-1.5", "-1.5");
            python_to_sqf("1234.0", "1234");
            python_to_sqf("12345.6", "12345.6");
        }

        TEST_METHOD(ListParsing)
        {
            python_to_sqf("[]", "[]");
            python_to_sqf("[True]", "[True]");
            python_to_sqf("[True, False]", "[True,False]");
            python_to_sqf("[[[]]]", "[[[]]]");
            python_to_sqf("[[0, 0], [0, 1], [0, 2]]", "[[0,0],[0,1],[0,2]]");

            // Slices
            python_to_sqf("[0, 1, 2, 3, 4, 5, 6][1:5]", "[1,2,3,4]");

            // Generated list
            python_to_sqf("[i for i in [True, True, False]]", "[True,True,False]");
            python_to_sqf("[i for i in range(5)]", "[0,1,2,3,4]");
        }

        TEST_METHOD(TupleParsing)
        {
            python_to_sqf("()", "[]");
            python_to_sqf("(True,)", "[True]");
            python_to_sqf("(True, False)", "[True,False]");
            python_to_sqf("(((),),)", "[[[]]]");
            python_to_sqf("((0, 0), (0, 1), (0, 2))", "[[0,0],[0,1],[0,2]]");

            // Slices
            python_to_sqf("(0, 1, 2, 3, 4, 5, 6)[1:5]", "[1,2,3,4]");

            // Other
            python_to_sqf("1, 2, 3", "[1,2,3]");
        }

        TEST_METHOD(GeneratorParsing)
        {
            python_to_sqf("(i for i in [True, True, False])", "[True,True,False]");
            python_to_sqf("(i for i in range(5))", "[0,1,2,3,4]");
            python_to_sqf("(i for i in [])", "[]"); // Empty generator
        }

        TEST_METHOD(RangeParsing)
        {
            python_to_sqf("range(5)", "[0,1,2,3,4]");
        }

        TEST_METHOD(SetParsing)
        {
            python_to_sqf("set([5])", "[5]");
            python_to_sqf("set([])", "[]");
        }

    };
}
