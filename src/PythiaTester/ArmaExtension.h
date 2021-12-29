#include <filesystem>

typedef void(__stdcall* RVExtension_t)(char* output, int outputSize, const char* function);
typedef void(__stdcall* RVExtensionVersion_t)(char* output, int outputSize);

#ifdef _WIN32
    typedef HINSTANCE libHandle_t;
#else
    typedef void* libHandle_t;
#endif

class ArmaExtension
{
    public:
    std::filesystem::path fullPath;

    private:
    libHandle_t handle;

    RVExtension_t rvextensionPtr;
    RVExtensionVersion_t rvextensionVersionPtr;

    public:
    ArmaExtension(std::filesystem::path path, std::string name, bool autoLoad = false)
    {
        name = fixName(name);
        fullPath = path / name;
        handle = nullptr;

        rvextensionPtr = nullptr;
        rvextensionVersionPtr = nullptr;

        if (autoLoad)
        {
            load();
        }
    }

    operator bool() const
    {
        return handle != nullptr;
    }

    bool hasRVExtension()
    {
        return !!rvextensionPtr;
    }

    bool hasRVExtensionVersion()
    {
        return !!rvextensionVersionPtr;
    }

    void RVExtension(char* output, const int outputSize, const char* function)
    {
        if(rvextensionPtr)
        {
            rvextensionPtr(output, outputSize, function);
        }
    }

    void RVExtensionVersion(char* output, const int outputSize)
    {
        if(rvextensionVersionPtr)
        {
            rvextensionVersionPtr(output, outputSize);
        }
    }

    void load()
    {
        #ifdef _WIN32
            handle = LoadLibrary(fullPath.c_str());
        #else
            handle = dlopen(fullPath.c_str(), RTLD_LAZY);
        #endif

        if(!handle)
        {
            return;
        }

        #if defined _WIN32 && !defined _WIN64
            rvextensionPtr = (RVExtension_t)getFunction("_RVExtension@12");
            rvextensionVersionPtr = (RVExtensionVersion_t)getFunction("_RVExtensionVersion@8");
        #else
            rvextensionPtr = (RVExtension_t)getFunction("RVExtension");
            rvextensionVersionPtr = (RVExtensionVersion_t)getFunction("RVExtensionVersion");
        #endif
    }

    void unload()
    {
        rvextensionPtr = nullptr;
        rvextensionVersionPtr = nullptr;

        #ifdef _WIN32
            FreeLibrary(handle);
        #else
            dlclose(handle);
        #endif
    }

    private:
    static std::string fixName(std::string name)
    {
        #if defined(_WIN64) || defined(__amd64__) || defined(_M_X64)
            name += "_x64";
        #endif

        #ifdef _WIN32
            name += ".dll";
        #else
            name += ".so";
        #endif
        return name;
    }

    void *getFunction(const char *name)
    {
        #ifdef _WIN32
            return GetProcAddress(handle, name);
        #else
            return dlsym(handle, name);
        #endif
    }
};
