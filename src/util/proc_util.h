#ifndef EVENT_LOGGER_UTIL_PROC_UTIL_H
#define EVENT_LOGGER_UTIL_PROC_UTIL_H

/*
 * File Notes:
 * - Single home for the /proc-reading helpers used to enrich process context.
 * - Previously duplicated across the enricher, the entity registry, and the
 *   sink cache; consolidated here so there is one authoritative implementation.
 */

#include <cstdint>
#include <string>

namespace event_logger::proc_util {

/** @brief Read a /proc symlink target into a string; empty on failure. */
std::string ReadProcSymlink(const std::string& path);

/** @brief Read a small text/binary file into a string; empty on failure. */
std::string ReadTextFile(const std::string& path, bool binary = false);

/** @brief Convert NUL-separated /proc/<pid>/cmdline into a space-separated string. */
std::string NormalizeCmdline(std::string raw);

/** @brief Strip trailing newlines/spaces from a proc text value in place. */
void RStrip(std::string* s);

/** @brief Parse the start-time (clock ticks) field from a /proc/<pid>/stat line. */
uint64_t ParseStartTimeTicks(const std::string& stat_line);

}  // namespace event_logger::proc_util

#endif
