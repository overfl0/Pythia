#pragma once
#include "third_party/spdlog/spdlog.h"

namespace Logger
{
    extern std::shared_ptr<spdlog::logger> logfile;
    std::string w2s(const std::wstring &var);
    std::wstring s2w(const std::string &var);
}

#define LOG_DEBUG Logger::logfile->debug
#define LOG_INFO Logger::logfile->info
#define LOG_WARN Logger::logfile->warn
#define LOG_ERROR Logger::logfile->error

#define LOG_FLUSH Logger::logfile->flush

std::shared_ptr<spdlog::logger> getFallbackLogger();
void createLogger(std::string loggerName, spdlog::filename_t loggerFile);
void switchToAsyncLogger(std::string loggerName, spdlog::filename_t loggerFile);
