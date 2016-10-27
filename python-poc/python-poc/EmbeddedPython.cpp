#include "stdafx.h"
#include "EmbeddedPython.h"
#include <Python.h>
#include <iostream>

EmbeddedPython *python = NULL;

EmbeddedPython::EmbeddedPython()
{
	std::cout << "Entering EmbeddedPython::EmbeddedPython()" << std::endl;

	Py_Initialize();

	PyObject *pName = PyUnicode_DecodeFSDefault("python-code/Adapter.py");
	if (pName)
	{
		pModule = PyImport_Import(pName);
		Py_DECREF(pName);

		if (pModule)
		{
			pFunc = PyObject_GetAttrString(pModule, "python_extension");
			if (!pFunc || PyCallable_Check(pFunc))
			{
				if (PyErr_Occurred())
				{
					PyErr_Print();
				}
				std::cout << "Failed to reference python function 'python_extension' from python-code/Adapter.py" << std::endl;
			}
			else
			{
				std::cout << "Python extension initialised";
			}
		}
		else
		{
			PyErr_Print();
			std::cout << "Failed to load python-code/Adapter.py" << std::endl;
		}
	}
	else
	{
		if (PyErr_Occurred())
		{
			PyErr_Print();
		}
		std::cout << "Failed to convert to python string 'python-code/Adapter.py'" << std::endl;
	}

	std::cout << "Leaving EmbeddedPython::EmbeddedPython()" << std::endl;
}

EmbeddedPython::~EmbeddedPython()
{
	std::cout << "Entering EmbeddedPython::~EmbeddedPython()" << std::endl;

	Py_XDECREF(pFunc);
	Py_XDECREF(pModule);

	Py_Finalize();

	std::cout << "Leaving EmbeddedPython::~EmbeddedPython()" << std::endl;
}

std::string EmbeddedPython::execute(const char * input)
{
	if (pFunc)
	{
		PyObject *pArgs = PyUnicode_FromString(input);
		if (pArgs)
		{
			PyObject *pResult = PyObject_CallObject(pFunc, pArgs);
			Py_DECREF(pArgs);

			if (pResult)
			{
				std::string result(PyUnicode_AsUTF8(pResult));
				Py_DECREF(pResult);

				// Hopefully RVO applies here
				return result;
			}
			else
			{
				PyErr_Print();
				throw std::runtime_error("Failed to execute python extension. See log file");
			}
		}
		else
		{
			std::cout << "Failed to transform to Unicode input #" << input << "#" << std::endl;
			throw std::runtime_error("Failed to transform the given input to Unicode. See log file");
		}
	}
	else
	{
		throw std::runtime_error("Python extension not initialised");
	}
}
