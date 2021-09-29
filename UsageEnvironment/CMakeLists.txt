
include_directories(include)

set(headers
  include/UsageEnvironment_version.hh
  include/UsageEnvironment.hh
  include/strDup.hh
  include/HashTable.hh
  include/Boolean.hh
  )

set(sources
  UsageEnvironment.cpp
  strDup.cpp
  HashTable.cpp
  )

add_library(UsageEnvironment
  ${headers} ${sources}
  )