#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ko {

enum class Direction { In, Out };

struct RawPacket {
  std::int64_t ts_unix_us = 0;
  Direction dir = Direction::In;
  std::vector<std::uint8_t> data;
};

// Şifreli gövdenin ilk baytı anahtar seçicidir (govde[0]).
//   1 = handshake ile gelen oturum anahtarı
//   2 = exe içine gömülü sabit anahtar (yalnızca okuma tarafında görülür)
// Eski `Client`/`Server` adları arayüzü kırmamak için alias olarak duruyor:
// Client = oturum anahtarı, Server = sabit anahtar.
enum class Cryption {
  Unknown = 0,
  Session = 1,
  Constant = 2,
  Client = Session,
  Server = Constant,
};

struct DecodedPacket {
  RawPacket raw;
  Cryption cryption = Cryption::Unknown;
  std::vector<std::uint8_t> plain;
  std::uint8_t opcode = 0;
  // Giden yönde şifreli gövdenin sıra numarası (1..250). Gelen yönde ve düz
  // modda her zaman 0'dır.
  std::uint8_t seq = 0;
  const char* opcode_name = "UNKNOWN";
  bool ok = false;
  std::string error;
};

}  // namespace ko
