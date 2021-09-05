#include "stdafx.h"
#include "Logger.h"
#include <memory>
#include <locale> // wstring_convert

std::shared_ptr<spdlog::logger> getFallbackLogger()
{
    constexpr const char *fallbackLoggerName = "Fallback_stderr";
    spdlog::drop(fallbackLoggerName);
    return spdlog::stderr_logger_mt(fallbackLoggerName);
}

void createLogger(std::string loggerName, spdlog::filename_t loggerFile)
{
    try
    {
        spdlog::set_level(spdlog::level::debug);
        spdlog::set_sync_mode();
        Logger::logfile = spdlog::rotating_logger_mt(loggerName, loggerFile, 1024 * 1024 * 10, 3);
    }
    catch (const spdlog::spdlog_ex& ex)
    {
        Logger::logfile = getFallbackLogger();
        LOG_ERROR(std::string("Could not create regular logger! ") + ex.what());
    }
}

// Do NOT call this function in dllmain.cpp!!!
// It creates new threads which is forbidden while attaching the dll
void switchToAsyncLogger(std::string loggerName, spdlog::filename_t loggerFile)
{
    LOG_INFO("Switching to asynchronous logger...");
    LOG_FLUSH();
    Logger::logfile = nullptr;
    spdlog::drop(loggerName);

    try
    {
        spdlog::set_level(spdlog::level::debug);
        spdlog::set_async_mode(131072, spdlog::async_overflow_policy::block_retry,
            nullptr,
            std::chrono::milliseconds(500));

        Logger::logfile = spdlog::rotating_logger_mt(loggerName, loggerFile, 1024 * 1024 * 10, 3);
        LOG_INFO("Switching to asynchronous logger done!");
    }
    catch (const spdlog::spdlog_ex& ex)
    {
        // Try creating the regular logger again. Might work.
        try
        {
            createLogger(loggerName, loggerFile);
        }
        catch (const spdlog::spdlog_ex& ex)
        {
            Logger::logfile = getFallbackLogger();
            LOG_ERROR(std::string("Could not create regular logger! ") + ex.what());
        }

        LOG_ERROR(std::string("Could not create asynchronous logger! ") + ex.what());
    }
}

namespace Logger
{
    std::string w2s(const std::wstring &var)
    {
        static std::locale loc("");
        auto &facet = std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(loc);
        return std::wstring_convert<std::remove_reference<decltype(facet)>::type, wchar_t>(&facet).to_bytes(var);
    }

    std::wstring s2w(const std::string &var)
    {
        static std::locale loc("");
        auto &facet = std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(loc);
        return std::wstring_convert<std::remove_reference<decltype(facet)>::type, wchar_t>(&facet).from_bytes(var);
    }
}
