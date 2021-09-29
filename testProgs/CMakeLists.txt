
include_directories(../liveMedia/include)

if(WIN32)
  set(system_lib Iphlpapi.lib ws2_32.lib)
else()
  set(system_lib ssl crypto)
endif()

set(shared_src announceURL.hh announceURL.cpp)
set(lib_list livemedia groupsock BasicUsageEnvironment UsageEnvironment)

add_executable(testMPEG4VideoStreamer
                testMPEG4VideoStreamer.cpp ${shared_src})

target_link_libraries(testMPEG4VideoStreamer ${lib_list} ${system_lib})
