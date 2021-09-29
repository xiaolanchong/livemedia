cmake_minimum_required(VERSION 3.15)

project(livemedia)

if(WIN32)
  #set(compiler_flags )
  add_compile_definitions(NO_OPENSSL=1)
  add_compile_options("/W4")
elseif(UNIX)
  # required: libssl-dev
  add_compile_definitions(SOCKLEN_T=socklen_t _LARGEFILE_SOURCE=1 BSD=1)
  add_compile_options(-Wall -m64 -fPIC -O2)
endif()

include_directories(BasicUsageEnvironment/include)
include_directories(UsageEnvironment/include)
include_directories(groupsock/include)

add_subdirectory(BasicUsageEnvironment)
add_subdirectory(groupsock)
add_subdirectory(liveMedia)
add_subdirectory(testProgs)
add_subdirectory(UsageEnvironment)
