#pragma once
#include <cstdint>
#include "core/types.h"

namespace ko {

// Bilinen WIZ opcode'lari icin okunabilir ad dondurur; bilinmeyen opcode icin "UNKNOWN".
const char* opcodeName(std::uint8_t opcode);

// Opcode'un bilinen tabloda olup olmadigini soyler.
bool isKnownOpcode(std::uint8_t opcode);

// Opcode'un beklenen yonu. Tablo henuz canli trafikle dogrulanmadi, IDA ajaninin
// ciktisi geldiginde bu bilgi kesinlesecek. Varsayilan `Direction::In` "iki yon de olabilir"
// anlaminda degil, "gelen yon" anlaminda kullanilir; yon ayrimi gerekmeyen yerlerde
// `opcodeDirection` yerine yalnizca ad kullanilmali.
Direction opcodeDirection(std::uint8_t opcode);

} // namespace ko
