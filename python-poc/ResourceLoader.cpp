#include "stdafx.h"
#include "ResourceLoader.h"
#include <iostream>

std::string ResourceLoader::loadTextResource(int id, LPTSTR type)
{
	std::cout << "Entering ResourceLoader::loadResource" << std::endl;

	HRSRC resourceHandle = ::FindResource(NULL, MAKEINTRESOURCE(id), type);
	
	if (!resourceHandle)
	{
		std::string msg("Unable to find resource with id: [");
		msg += std::to_string(id);
		msg += "] because of error with code: ";
		msg += std::to_string(::GetLastError());

		throw std::runtime_error(msg);
	}

	HGLOBAL resourceData = ::LoadResource(NULL, resourceHandle);
	LPVOID dataFirstByte = ::LockResource(resourceData);

	// LockResource: to obtain a pointer to the first byte of the resource data
	std::cout << "Leaving ResourceLoader::loadResource" << std::endl;
	return std::string(static_cast<const char*>(dataFirstByte));
}
