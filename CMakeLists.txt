cmake_minimum_required(VERSION 3.20)
project(eTraceGen LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(EVENT_LOGGER_WITH_LIBBPF "Enable libbpf-backed collector" ON)

add_executable(etracegen
  src/main.cpp
  src/decoder/decoder.cpp
  src/enricher/enricher.cpp
  src/policy/policy.cpp
  src/sinks/json_sink.cpp
  src/metrics/metrics.cpp
)

target_include_directories(etracegen PRIVATE include src)

target_compile_options(etracegen PRIVATE -Wall -Wextra -Wpedantic)

# Linux-only helper target for reproducible BPF object generation.
# This target is opt-in and does not run during the default C++ build.
add_custom_target(bpf_object
  COMMAND "${CMAKE_SOURCE_DIR}/scripts/build_bpf.sh"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Build eTraceGen BPF object (bpf/event_logger.bpf.o)"
)

if(EVENT_LOGGER_WITH_LIBBPF)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBBPF QUIET libbpf)
  endif()
endif()

if(LIBBPF_FOUND)
  message(STATUS "Building with libbpf backend")
  target_sources(etracegen PRIVATE src/collector/collector_libbpf.cpp)
  target_include_directories(etracegen PRIVATE ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(etracegen PRIVATE ${LIBBPF_LIBRARIES})
  target_compile_definitions(etracegen PRIVATE
    EVENT_LOGGER_HAVE_LIBBPF=1
    EVENT_LOGGER_DEFAULT_BPF_OBJECT="${CMAKE_SOURCE_DIR}/bpf/event_logger.bpf.o"
  )
else()
  message(WARNING "libbpf not found. Building stub collector backend.")
  target_sources(etracegen PRIVATE src/collector/collector_stub.cpp)
endif()
