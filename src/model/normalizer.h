#ifndef EVENT_LOGGER_MODEL_NORMALIZER_H
#define EVENT_LOGGER_MODEL_NORMALIZER_H

/*
 * File Notes:
 * - Declares the raw-to-canonical normalization stage.
 * - Purely structural and stateless: it classifies domain/action/outcome and
 *   extracts actor + object descriptors. Entity resolution (assigning stable
 *   EntityRef ids) is the EntityRegistry's job, not the Normalizer's.
 */

#include "decoder/decoder.h"
#include "model/canonical_event.h"

namespace event_logger {

/**
 * @brief Maps a raw typed event onto a kernel-agnostic CanonicalEvent.
 */
class Normalizer {
 public:
  /**
   * @brief Normalize one raw event into canonical form.
   *
   * @param raw Decoded raw event variant. The returned CanonicalEvent holds a
   *            non-owning pointer to it, so `raw` must outlive the result's use.
   * @return Canonical event with domain/action/outcome/actor/object populated
   *         and EntityRefs left unresolved (id == 0).
   */
  CanonicalEvent Normalize(const EventVariant& raw) const;
};

}  // namespace event_logger

#endif
