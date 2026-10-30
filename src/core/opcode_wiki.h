#pragma once

#include "core/types.h"

namespace ko {

// Opcode tablosundan Markdown protokol wikisi uretir. Canli yakalama gerektirmez:
// tablo derleme zamaninda sabit oldugu icin wiki her zaman acilabilir.
//
// Tum protokol wikisini uretir (cerceve, govde modlari, gelen ve giden opcode
// tablolari). Canli yakalama gerektirmez: tablo derleme zamaninda sabittir.
std::string buildOpcodeWiki();

// Cozulmus govde yerlesimi: "offset  tip  ad" satirlari. `payload` cozulmus
// duz metindir (opcode govdenin 0. offsetindedir).
std::string buildLayoutTable(const DecodedPacket& payload);

} // namespace ko
