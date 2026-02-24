#ifndef EVENT_LOGGER_ENRICHER_H
#define EVENT_LOGGER_ENRICHER_H

/*
 * File Notes:
 * - Declares optional context enrichment stage after decode and before policy/sink.
 * - Intended for metadata additions that are expensive or unavailable in kernel.
 */

#include "decoder/decoder.h"

namespace event_logger {

/**
 * @brief Enrichment stage for augmenting typed events with extra context.
 */
class Enricher {
 public:
  /**
   * @brief Enrich event payload in place.
   *
   * @param event Decoded event variant that may be augmented with context.
   */
  void Enrich(EventVariant& event) const;
};

}  // namespace event_logger

#endif
