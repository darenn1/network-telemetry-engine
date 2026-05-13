#pragma once

#include <string>

namespace utils {

enum class LogLevel {
    INFO  = 0,
    WARN  = 1,
    ERROR = 2
};

class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel level);

    void info (const std::string& message);
    void warn (const std::string& message);
    void error(const std::string& message);
    void log  (LogLevel level, const std::string& message);

    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;

private:
    Logger();  

    LogLevel    level_{LogLevel::INFO};
    struct Impl;
    Impl* impl_;
};


void log_info (const std::string& message);
void log_warn (const std::string& message);
void log_error(const std::string& message);

} 