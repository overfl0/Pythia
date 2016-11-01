#pragma once
#include <fstream>

#define LOG_TRACE(_msg_) if (Logger::trace   >= Logger::logger().getLevel())    { Logger::logger().log() << "TRACE: " << _msg_ << std::endl; }
#define LOG_DEBUG(_msg_) if (Logger::debug   >= Logger::logger().getLevel())    { Logger::logger().log() << "DEBUG: " << _msg_ << std::endl; }
#define LOG_INFO(_msg_)  if (Logger::info    >= Logger::logger().getLevel())    { Logger::logger().log() << "INFO: " << _msg_ << std::endl;  }
#define LOG_WARN(_msg_)  if (Logger::warning >= Logger::logger().getLevel())    { Logger::logger().log() << "WARN: " << _msg_ << std::endl;  }
#define LOG_ERROR(_msg_) if (Logger::error   >= Logger::logger().getLevel())    { Logger::logger().log() << "ERROR: " << _msg_ << std::endl; }

class Logger
{
public:
    enum Level { trace, debug, info, warning, error, off };
public:
    static Logger& logger()
    {
        static Logger instance;
        return instance;
    }

    virtual ~Logger()
    {
        logFile.close();
    }

    std::ofstream& log()
    {
        return logFile;
    }

    Level getLevel()
    {
        return level;
    }

private:
    Logger::Logger() : logFile(Logger::makeFilename()), level(info)
    {
    }
    static std::string makeFilename();

    Logger(const Logger&) = delete;
    void operator=(const Logger&) = delete;

private:
    std::ofstream logFile;
    Level level;
};
