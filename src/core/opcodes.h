#pragma once
#include <cstdint>
#include "core/types.h"

namespace ko {

// Bir govde alaninin tipi. `Coord` = u16 okunup 10.0'a bolunen dunya koordinati.
enum class FieldType : std::uint8_t { U8, U16, U32, U64, F32, Coord, Str };

// Tek bir alan: govde icindeki offset (0 = opcode), tipi ve adi.
struct FieldSpec {
  std::uint16_t offset;
  FieldType type;
  const char* name;
};

// Bir opcode'un tam kaydi.
struct OpcodeInfo {
  std::uint8_t opcode;
  const char* name;
  Direction dir;              // Yon; su an tablo yalnizca alim yolunu kapsiyor.
  const FieldSpec* fields;    // nullptr = govde okunmuyor.
  std::uint8_t fieldCount;
  bool provisional;           // true = ad/yon/alanlar canli trafikle dogrulanmadi.
  bool fieldsTruncated;       // true = string/skip sonrasi alan listesi eksik.
  bool special;               // true = pkt_dispatch_main'de ozel islenir, base'e dusmez.
  bool variant;               // true = offset 1'de alt secici bayt var, govde ona gore degisir.
};

// Opcode + yon icin kayit dondurur; tabloda yoksa nullptr.
const OpcodeInfo* findOpcode(std::uint8_t opcode, Direction dir);

// Bilinen opcode'lar icin okunabilir ad dondurur; bilinmeyen opcode icin "UNKNOWN".
const char* opcodeName(std::uint8_t opcode);

// Opcode'un bilinen tabloda olup olmadigini soyler.
bool isKnownOpcode(std::uint8_t opcode);

// Opcode'un beklenen yonu. Tablo su an yalnizca alim yolundan cikarildi,
// bu yuzden bilinmeyen opcode icin `Direction::In` doner.
Direction opcodeDirection(std::uint8_t opcode);

} // namespace ko
