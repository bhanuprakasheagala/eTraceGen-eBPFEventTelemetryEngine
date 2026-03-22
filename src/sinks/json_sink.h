#ifndef EVENT_LOGGER_JSON_SINK_H
#define EVENT_LOGGER_JSON_SINK_H

/*
 * File Notes:
 * - Concrete sink that renders events as line-delimited JSON objects.
 * - File-only sink with max-size rollover.
 */

#include <cstdint>
#include <fstream>
#include <ostream>
#include <string>

#include "sinks/sink.h"

namespace event_logger {

/**
 * @brief Sink that writes one JSON object per event line into a file.
 */
class JsonSink final : public Sink {
 public:
  /**
   * @brief Construct file-backed JSON sink.
   *
   * File is opened in append mode. When size reaches limit, sink deletes the
   * file and starts a new one.
   *
   * @param file_path Destination NDJSON file path.
   * @param max_file_size_bytes Max bytes before rollover. 0 disables rollover.
   */
  JsonSink(std::string file_path, uint64_t max_file_size_bytes);

  /**
   * @brief Return true when sink is ready to write events.
   */
  bool IsReady() const { return ready_; }

  /**
   * @brief Serialize and write one typed event as JSON.
   */
  void Write(const EventVariant& event) override;

 private:
  bool OpenFileAppend();
  bool RotateIfNeeded(size_t next_record_bytes);

  std::ofstream file_out_;
  std::string file_path_;
  uint64_t max_file_size_bytes_ = 0;
  uint64_t current_file_size_bytes_ = 0;
  bool ready_ = false;
};

}  // namespace event_logger

#endif
