#include "ui/log_writer.h"

#include <ctime>

namespace ko::ui {
namespace {

const char* dirName(Direction dir) { return dir == Direction::In ? "GELEN" : "GIDEN"; }

const char* cryptionName(Cryption cryption) {
  switch (cryption) {
    case Cryption::Client: return "client";
    case Cryption::Server: return "server";
    case Cryption::Unknown: return "bilinmiyor";
  }
  return "bilinmiyor";
}

// Zaman damgasini okunabilir saate cevirir.
std::string formatTime(std::int64_t tsUnixUs) {
  const std::time_t seconds = static_cast<std::time_t>(tsUnixUs / 1'000'000);
  const int millis = static_cast<int>((tsUnixUs % 1'000'000) / 1'000);
  std::tm tm{};
  localtime_s(&tm, &seconds);
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
  return buffer;
}

void appendHex(std::string& out, const std::uint8_t* data, std::size_t len) {
  constexpr char digits[] = "0123456789ABCDEF";
  out.push_back(' ');
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 0x0F]);
    out.push_back(' ');
  }
}

} // namespace

LogWriter::~LogWriter() { close(); }

bool LogWriter::open(const std::string& path, std::string& error) {
  close();
  file_.open(path, std::ios::out | std::ios::trunc | std::ios::binary);
  if (!file_) {
    error = "log dosyasi acilamadi: " + path;
    return false;
  }
  path_ = path;
  written_ = 0;
  file_ << "# KoPacketLogger kaydi\n";
  file_.flush();
  return true;
}

void LogWriter::close() {
  if (file_.is_open()) {
    file_.flush();
    file_.close();
  }
}

std::size_t LogWriter::write(const DecodedPacket& packet) {
  if (!file_.is_open()) {
    return 0;
  }

  std::string line;
  line.reserve(packet.raw.data.size() * 3 + 128);
  line += formatTime(packet.raw.ts_unix_us);
  line += "  ";
  line += dirName(packet.raw.dir);
  line += "  op=0x";
  constexpr char digits[] = "0123456789ABCDEF";
  line.push_back(digits[packet.opcode >> 4]);
  line.push_back(digits[packet.opcode & 0x0F]);
  line += "  ";
  line += packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN";
  line += "  len=";
  line += std::to_string(packet.raw.data.size());
  line += "  cryp=";
  line += cryptionName(packet.cryption);
  if (!packet.ok) {
    line += "  HATA=";
    line += packet.error;
  }
  line += "\n    ham:";
  appendHex(line, packet.raw.data.data(), packet.raw.data.size());
  if (!packet.plain.empty()) {
    line += "\n    duz:";
    appendHex(line, packet.plain.data(), packet.plain.size());
  }
  line += '\n';

  file_ << line;
  if ((written_ & 0x3F) == 0) {
    file_.flush();
  }
  ++written_;
  return line.size();
}

} // namespace ko::ui
