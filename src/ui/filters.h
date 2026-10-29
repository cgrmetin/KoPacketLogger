#pragma once

#include <cstdint>
#include <string>

#include "core/types.h"

namespace ko::ui {

// Kullaniciya ait canli filtre alanlari (ImGui widget'lari bunlara baglanir).
struct FilterState {
  bool showIn = true;
  bool showOut = true;

  bool opcodeRangeEnabled = false;
  int opcodeMin = 0;
  int opcodeMax = 0xFF;

  bool nameContainsEnabled = false;
  char nameContains[64] = {};

  bool sizeRangeEnabled = false;
  int sizeMin = 0;
  int sizeMax = 65535;

  bool textEnabled = false;
  char text[128] = {};

  bool errorsOnly = false;

  // Alanlardan herhangi biri sonucu daraltiyor mu.
  bool active() const;
  // Iki anlik goruntu ayni mi; yeniden kurma gerekip gerekmedigini anlamak icin.
  bool sameAs(const FilterState& other) const;
};

// FilterState'in onden hesaplanmis, her pakette tahsis yapmayan hali.
struct PreparedFilter {
  bool showIn = true;
  bool showOut = true;
  bool errorsOnly = false;

  bool opcodeRange = false;
  int opcodeMin = 0;
  int opcodeMax = 0xFF;

  bool nameContains = false;
  std::string nameNeedle; // kucuk harfe cevrilmis

  bool sizeRange = false;
  int sizeMin = 0;
  int sizeMax = 65535;

  bool text = false;
  std::string textNeedle; // kucuk harfe cevrilmis

  bool matches(const DecodedPacket& packet) const;
};

PreparedFilter prepare(const FilterState& state);

} // namespace ko::ui
