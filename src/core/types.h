#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
namespace ko {
enum class Direction { In, Out };
struct RawPacket { std::int64_t ts_unix_us; Direction dir; std::vector<std::uint8_t> data; };
enum class Cryption { Unknown, Client, Server };
struct DecodedPacket {
  RawPacket raw; Cryption cryption = Cryption::Unknown;
  std::vector<std::uint8_t> plain; std::uint8_t opcode = 0; const char* opcode_name = "UNKNOWN";
  bool ok = false; std::string error;
};
}
