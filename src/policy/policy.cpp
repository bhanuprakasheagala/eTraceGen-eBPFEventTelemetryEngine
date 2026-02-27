/*
 * File Notes:
 * - Minimal pass-through policy implementation.
 * - Structured as a dedicated stage so richer filtering can be added without main-loop churn.
 */

#include "policy/policy.h"

namespace event_logger {

/**
 * @brief Decide whether event is allowed to continue.
 *
 * @param event Typed event payload (unused in current permissive policy).
 * @return true always in current baseline policy.
 */
bool PolicyEngine::Allow(const EventVariant& /*event*/) const {
  return true;
}

}  // namespace event_logger
