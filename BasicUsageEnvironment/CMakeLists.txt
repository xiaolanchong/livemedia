
include_directories(include)

set(headers
  include/BasicHashTable.hh
  include/BasicUsageEnvironment.hh
  include/BasicUsageEnvironment_version.hh
  include/BasicUsageEnvironment0.hh
  include/DelayQueue.hh
  include/HandlerSet.hh
  )

set(sources
  BasicHashTable.cpp
  BasicTaskScheduler.cpp
  BasicTaskScheduler0.cpp
  BasicUsageEnvironment.cpp
  BasicUsageEnvironment0.cpp
  DelayQueue.cpp
  )

add_library(BasicUsageEnvironment
  ${headers} ${sources}
  )