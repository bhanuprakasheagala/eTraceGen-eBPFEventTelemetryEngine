cmake_minimum_required(VERSION 3.20)
project(eTraceGen LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "eTraceGen is Linux-only. Build on a Linux host.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(etracegen
  src/main.cpp
  src/decoder/decoder.cpp
  src/enricher/enricher.cpp
  src/policy/policy.cpp
  src/sinks/json_sink.cpp
  src/metrics/metrics.cpp
  src/collector/collector_libbpf.cpp
)

target_include_directories(etracegen PRIVATE include src)
target_compile_options(etracegen PRIVATE -Wall -Wextra -Wpedantic)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

message(STATUS "Building Linux libbpf collector backend")
target_include_directories(etracegen PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(etracegen PRIVATE ${LIBBPF_LIBRARIES})
target_compile_definitions(etracegen PRIVATE
  EVENT_LOGGER_HAVE_LIBBPF=1
  EVENT_LOGGER_DEFAULT_BPF_OBJECT="${CMAKE_SOURCE_DIR}/bpf/event_logger.bpf.o"
)

# Linux-only helper target for reproducible BPF object generation.
add_custom_target(bpf_object
  COMMAND "${CMAKE_SOURCE_DIR}/scripts/linux.sh" bpf
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Build eTraceGen BPF object (bpf/event_logger.bpf.o)"
)
