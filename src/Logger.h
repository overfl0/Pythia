#pragma once
#include <fstream>
#include "third_party/spdlog/spdlog.h"

namespace Logger
{
    extern std::shared_ptr<spdlog::logger> logfile;
}

#define LOG_DEBUG Logger::logfile->debug
#define LOG_INFO Logger::logfile->info
#define LOG_WARN Logger::logfile->warn
#define LOG_ERROR Logger::logfile->error

//spdlogger = spdlog::rotating_logger_mt("some_logger_name", "logs/mylogfile.txt", 1048576 * 5, 3);
