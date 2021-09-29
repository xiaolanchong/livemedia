
include_directories(include)

set(headers
  include/NetCommon.h
  include/GroupEId.hh
  include/Groupsock.hh
  include/groupsock_version.hh
  include/GroupsockHelper.hh
  include/IOHandlers.hh
  include/NetAddress.hh
  include/NetInterface.hh
  )

set(sources
  inet.c
  GroupEId.cpp
  Groupsock.cpp
  GroupsockHelper.cpp
  IOHandlers.cpp
  NetAddress.cpp
  NetInterface.cpp
  )

if(WIN32)
  list(APPEND headers ifaddrs.h)
  list(APPEND sources getifaddr.c)
endif()

add_library(groupsock
  ${headers} ${sources}
  )