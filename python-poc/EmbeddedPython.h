#pragma once

// Forward declarations
#include <Python.h>
#include <string>

class EmbeddedPython
{
public:
	EmbeddedPython();
	virtual ~EmbeddedPython();
	
	std::string execute(const char* input);
	std::string getExceptionDescription();

private:
	PyObject *pModule;
	PyObject *pFunc;
};

