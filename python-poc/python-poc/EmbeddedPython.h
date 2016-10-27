#pragma once

// Forward declarations
class PyObject;
#include <string>

class EmbeddedPython
{
public:
	EmbeddedPython();
	virtual ~EmbeddedPython();
	
	std::string execute(const char* input);

private:
	PyObject *pModule;
	PyObject *pFunc;
};

