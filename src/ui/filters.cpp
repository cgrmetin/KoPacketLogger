#include "ui/filters.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string_view>

namespace ko::ui {
namespace {

char toLowerAscii(char c) noexcept {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Tahsis yapmadan, kaynak metnin kucuk harfli karsiligi `needle` icermiyor mu.
bool containsInsensitive(const char* haystackBegin, const char* haystackEnd, std::string_view needle) {
  if (needle.empty()) return true;
  const auto hayLen = static_cast<std::ptrdiff_t>(haystackEnd - haystackBegin);
  const auto needleLen = static_cast<std::ptrdiff_t>(needle.size());
  if (needleLen > hayLen) return false;

  for (std::ptrdiff_t i = 0; i + needleLen <= hayLen; ++i) {
    std::ptrdiff_t matched = 0;
    for (; matched < needleLen; ++matched) {
      if (toLowerAscii(haystackBegin[i + matched]) != needle[static_cast<std::size_t>(matched)]) break;
    }
    if (matched == needleLen) return true;
  }
  return false;
}

// Ham baytlar hexadecimal metin olarak aranir; tahsis yapmadan.
bool hexContains(const std::vector<std::uint8_t>& data, std::string_view needle) {
  if (needle.empty() || data.empty()) return false;

  // "0x" girisini yok say.
  if (needle.size() >= 2 && needle[0] == '0' && needle[1] == 'x') {
    needle.remove_prefix(2);
    while (!needle.empty() && needle.front() == ' ') needle.remove_prefix(1);
  }
  if (needle.empty()) return true;

  constexpr char kHexDigits[] = "0123456789abcdef";

  // Onaltilik dizi seklinde ara (bosluksuz): 4a -> 4,a.
  if (needle.size() >= 2) {
    const auto totalNibbles = static_cast<std::ptrdiff_t>(data.size()) * 2;
    const auto needleLen = static_cast<std::ptrdiff_t>(needle.size());
    for (std::ptrdiff_t i = 0; i + needleLen <= totalNibbles; ++i) {
      std::ptrdiff_t matched = 0;
      for (; matched < needleLen; ++matched) {
        const std::ptrdiff_t pos = i + matched;
        const std::uint8_t byte = data[static_cast<std::size_t>(pos >> 1)];
        const char nibble = ((pos & 1) == 0) ? kHexDigits[byte >> 4] : kHexDigits[byte & 0x0F];
        if (toLowerAscii(nibble) != needle[static_cast<std::size_t>(matched)]) break;
      }
      if (matched == needleLen) return true;
    }
  }
  return false;
}

bool textMatchesAny(const DecodedPacket& packet, std::string_view needle) {
  const char* opcodeBegin = packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN";
  const char* opcodeEnd = opcodeBegin + std::strlen(opcodeBegin);
  if (containsInsensitive(opcodeBegin, opcodeEnd, needle)) return true;

  const char* plainBegin = reinterpret_cast<const char*>(packet.plain.data());
  const char* plainEnd = plainBegin + packet.plain.size();
  if (containsInsensitive(plainBegin, plainEnd, needle)) return true;

  if (containsInsensitive(packet.error.data(), packet.error.data() + packet.error.size(), needle)) return true;

  // Ayrica onaltilik karsiligi da dene: "00 2F" gibi girisler baytlari bulur.
  if (hexContains(packet.raw.data, needle)) return true;

  return false;
}

std::string toLowerCopy(const char* text) {
  std::string out(text != nullptr ? text : "");
  for (char& c : out) c = toLowerAscii(c);
  while (!out.empty() && out.front() == ' ') out.erase(out.begin());
  while (!out.empty() && out.back() == ' ') out.pop_back();
  return out;
}

} // namespace

bool FilterState::active() const {
  return !showIn || !showOut || opcodeRangeEnabled || nameContainsEnabled || sizeRangeEnabled || textEnabled || errorsOnly;
}

bool FilterState::sameAs(const FilterState& other) const {
  return showIn == other.showIn && showOut == other.showOut && opcodeRangeEnabled == other.opcodeRangeEnabled &&
         opcodeMin == other.opcodeMin && opcodeMax == other.opcodeMax && nameContainsEnabled == other.nameContainsEnabled &&
         std::strncmp(nameContains, other.nameContains, sizeof(nameContains)) == 0 &&
         sizeRangeEnabled == other.sizeRangeEnabled && sizeMin == other.sizeMin && sizeMax == other.sizeMax &&
         textEnabled == other.textEnabled && std::strncmp(text, other.text, sizeof(text)) == 0 &&
         errorsOnly == other.errorsOnly;
}

PreparedFilter prepare(const FilterState& state) {
  PreparedFilter out;
  out.showIn = state.showIn;
  out.showOut = state.showOut;
  out.errorsOnly = state.errorsOnly;

  out.opcodeRange = state.opcodeRangeEnabled;
  out.opcodeMin = std::clamp(state.opcodeMin, 0, 0xFF);
  out.opcodeMax = std::clamp(state.opcodeMax, 0, 0xFF);
  if (out.opcodeMin > out.opcodeMax) std::swap(out.opcodeMin, out.opcodeMax);

  out.nameContains = state.nameContainsEnabled;
  out.nameNeedle = toLowerCopy(state.nameContains);

  out.sizeRange = state.sizeRangeEnabled;
  out.sizeMin = std::max(0, state.sizeMin);
  out.sizeMax = std::max(0, state.sizeMax);
  if (out.sizeMin > out.sizeMax) std::swap(out.sizeMin, out.sizeMax);

  out.text = state.textEnabled;
  out.textNeedle = toLowerCopy(state.text);

  return out;
}

bool PreparedFilter::matches(const DecodedPacket& packet) const {
  const bool incoming = packet.raw.dir == Direction::In;
  if (incoming && !showIn) return false;
  if (!incoming && !showOut) return false;
  if (errorsOnly && packet.ok) return false;

  if (opcodeRange && (packet.opcode < opcodeMin || packet.opcode > opcodeMax)) return false;

  if (nameContains && !nameNeedle.empty()) {
    const char* opcodeBegin = packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN";
    const char* opcodeEnd = opcodeBegin + std::strlen(opcodeBegin);
    if (!containsInsensitive(opcodeBegin, opcodeEnd, nameNeedle)) return false;
  }

  if (sizeRange) {
    const auto size = static_cast<int>(packet.raw.data.size());
    if (size < sizeMin || size > sizeMax) return false;
  }

  if (text && !textNeedle.empty() && !textMatchesAny(packet, textNeedle)) return false;

  return true;
}

} // namespace ko::ui
