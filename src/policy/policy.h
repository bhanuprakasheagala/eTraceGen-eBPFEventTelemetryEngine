#ifndef EVENT_LOGGER_POLICY_H
#define EVENT_LOGGER_POLICY_H

/*
 * File Notes:
 * - Declares policy stage that decides whether an event should be emitted downstream.
 * - Keeps filtering decisions centralized and testable.
 */

#include "decoder/decoder.h"

namespace event_logger {

/**
 * @brief Event policy evaluation stage.
 */
class PolicyEngine {
 public:
  /**
   * @brief Evaluate whether event should pass to sink.
   *
   * @param event Typed event payload.
   * @return true when event is allowed.
   * @return false when event should be suppressed.
   */
  bool Allow(const EventVariant& event) const;
};

}  // namespace event_logger

#endif
