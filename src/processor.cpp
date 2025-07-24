#include "processor.h"
#include "linux_parser.h"

// TODO: Return the aggregate CPU utilization
float Processor::Utilization()
{
    long active_jiffies = LinuxParser::ActiveJiffies();
  long idle_jiffies = LinuxParser::IdleJiffies();
  long total_jiffies = active_jiffies + idle_jiffies;
  
  // Protect against division by zero
  if (total_jiffies == 0) {
    return 0.0;
  }
  
  // Calculate utilization as the fraction of active jiffies
  return static_cast<float>(active_jiffies) / static_cast<float>(total_jiffies);
}