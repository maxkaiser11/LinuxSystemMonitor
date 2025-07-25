#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"
#include "linux_parser.h"

using std::string;
using std::to_string;
using std::vector;

Process::Process(int pid) : pid_(pid) {};

// TODO: Return this process's ID
int Process::Pid()
{
    return pid_;
}

// TODO: Return this process's CPU utilization
float Process::CpuUtilization() const
{
    long total_time = LinuxParser::ActiveJiffies(pid_);
  long seconds = LinuxParser::UpTime(pid_);
  long hz = sysconf(_SC_CLK_TCK);
  float cpu_usage = 0.0;
  if (seconds > 0) {
    cpu_usage = ((float)total_time / hz) / seconds;
  }
  return cpu_usage;
}

// TODO: Return the command that generated this process
string Process::Command()
{
     return LinuxParser::Command(pid_);
}

// TODO: Return this process's memory utilization
string Process::Ram()
{
    return LinuxParser::Ram(pid_);
}

// TODO: Return the user (name) that generated this process
string Process::User()
{
    return LinuxParser::User(pid_);
}

// TODO: Return the age of this process (in seconds)
long int Process::UpTime() const
{
    return LinuxParser::UpTime(pid_);
}

// TODO: Overload the "less than" comparison operator for Process objects
// REMOVE: [[maybe_unused]] once you define the function
bool Process::operator<(Process const& a[[maybe_unused]]) const{
    return this->CpuUtilization() < a.CpuUtilization();
}