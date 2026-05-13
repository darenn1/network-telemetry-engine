#include "utils/logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

namespace utils {

struct Logger::Impl {
    std::mutex mtx;
};

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger()
    : impl_(new Impl{})
{
}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    level_ = level;
}

void Logger::log(LogLevel level, const std::string& message) {

    if (level < level_) return;

    const auto now     = std::chrono::system_clock::now();
    const auto ms      = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now.time_since_epoch()
                         ).count() % 1000;
    const std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::ostringstream oss;

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);

        oss << "[";
        oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
        oss << "." << std::setfill('0') << std::setw(3) << ms;
        oss << "] ";

        switch (level) {
            case LogLevel::INFO:  oss << "[INFO]  "; break;
            case LogLevel::WARN:  oss << "[WARN]  "; break;
            case LogLevel::ERROR: oss << "[ERROR] "; break;
        }

        oss << message << "\n";

        std::cout << oss.str();
        std::cout.flush();
    }
}


void Logger::info (const std::string& msg) { log(LogLevel::INFO,  msg); }
void Logger::warn (const std::string& msg) { log(LogLevel::WARN,  msg); }
void Logger::error(const std::string& msg) { log(LogLevel::ERROR, msg); }


void log_info (const std::string& msg) { Logger::instance().info(msg);  }
void log_warn (const std::string& msg) { Logger::instance().warn(msg);  }
void log_error(const std::string& msg) { Logger::instance().error(msg); }

}