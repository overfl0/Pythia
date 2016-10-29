#include "stdafx.h"
#include "EmbeddedPython.h"
#include "ResourceLoader.h"
#include <iostream>
#include "resource.h"

EmbeddedPython *python = NULL;

std::string EmbeddedPython::getExceptionDescription()
{
	PyObject *ptype, *pvalue, *ptraceback;
	PyErr_Fetch(&ptype, &pvalue, &ptraceback);
	std::string errorMessage = PyUnicode_AsUTF8(pvalue);

	// TODO: Check if we should do a decref now?

	return errorMessage;
}

EmbeddedPython::EmbeddedPython()
{
	std::cout << "Entering EmbeddedPython::EmbeddedPython" << std::endl;

	Py_Initialize();

	std::cout << "Loading Python entry point" << std::endl;
	//PyObject *pName = PyUnicode_DecodeFSDefault(ResourceLoader::loadTextResource(PYTHON_ADAPTER, TEXT("PYTHON")).c_str());
	PyObject *pName = PyUnicode_DecodeFSDefault("python.Adapter"); // Until the above is fixed, use a junction called "python" to point to where adapter.py is.
	if (pName)
	{
		pModule = PyImport_Import(pName);
		Py_DECREF(pName);

		if (pModule)
		{
			pFunc = PyObject_GetAttrString(pModule, "python_extension");
			if (!pFunc || !PyCallable_Check(pFunc))
			{
				if (PyErr_Occurred())
				{
					std::string errorMessage = getExceptionDescription();
					std::cout << errorMessage;
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
			std::string errorMessage = getExceptionDescription();
			std::cout << errorMessage;
			std::cout << "Failed to load python-code/Adapter.py" << std::endl;
		}
	}
	else
	{
		if (PyErr_Occurred())
		{
			std::string errorMessage = getExceptionDescription();
			std::cout << errorMessage;
		}
		std::cout << "Failed to convert to python string 'python-code/Adapter.py'" << std::endl;
	}

	std::cout << "Leaving EmbeddedPython::EmbeddedPython" << std::endl;
}

EmbeddedPython::~EmbeddedPython()
{
	std::cout << "Entering EmbeddedPython::~EmbeddedPython" << std::endl;

	Py_XDECREF(pFunc);
	Py_XDECREF(pModule);

	Py_Finalize();

	std::cout << "Leaving EmbeddedPython::~EmbeddedPython" << std::endl;
}

std::string EmbeddedPython::execute(const char * input)
{
	if (pFunc)
	{
		PyObject *pArgs = PyUnicode_FromString(input);
		if (pArgs)
		{
			PyObject *tuple = PyTuple_Pack(1, pArgs);
			Py_DECREF(pArgs);

			if (!tuple)
			{
				throw std::runtime_error("Failed to convert argument string to tuple");
			}

			PyObject *pResult = PyObject_CallObject(pFunc, tuple);
			Py_DECREF(tuple);

			if (pResult)
			{
				std::string result(PyUnicode_AsUTF8(pResult));
				Py_DECREF(pResult);

				// Hopefully RVO applies here
				return result;
			}
			else
			{
				std::string errorMessage = getExceptionDescription();
				//throw std::runtime_error("Failed to execute python extension. See log file");
				throw std::runtime_error(errorMessage);
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
