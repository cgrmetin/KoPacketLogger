#include "core/frame.h"

#include <cstring>

namespace ko {
namespace {

// Little-endian 16 bit gövde uzunluğu okur.
std::size_t readLength(const std::uint8_t* p) noexcept {
  return static_cast<std::size_t>(p[0]) | (static_cast<std::size_t>(p[1]) << 8);
}

// Sihir/kuyruk sabitleri kablo bayt sırasıyla yazıldığı için karşılaştırma
// doğrudan bayt çifti üzerinden yapılır; ntohs gerekmez.
bool hasMagic(const std::uint8_t* p) noexcept {
  return p[0] == 0xAA && p[1] == 0x55;
}

bool hasTrailer(const std::uint8_t* p) noexcept {
  return p[0] == 0x55 && p[1] == 0xAA;
}

}  // namespace

const char* frameStatusName(FrameStatus status) noexcept {
  switch (status) {
    case FrameStatus::NeedMore: return "need more bytes";
    case FrameStatus::Ok: return "ok";
    case FrameStatus::Resynced: return "stream resynchronised";
    case FrameStatus::Overflow: return "stream buffer overflow";
  }
  return "unknown";
}

FrameParser::FrameParser(std::size_t maxFrameBytes, std::size_t maxBufferedBytes)
    : maxFrameBytes_(maxFrameBytes), maxBufferedBytes_(maxBufferedBytes) {
  if (maxFrameBytes_ < kMinFrameBytes) maxFrameBytes_ = kMinFrameBytes;
  if (maxBufferedBytes_ < maxFrameBytes_) maxBufferedBytes_ = maxFrameBytes_;
}

std::vector<std::uint8_t>& FrameParser::bufferFor(Direction dir) noexcept {
  return dir == Direction::In ? in_ : out_;
}

void FrameParser::reset(Direction dir) noexcept { bufferFor(dir).clear(); }

void FrameParser::resetAll() noexcept {
  in_.clear();
  out_.clear();
}

std::size_t FrameParser::buffered(Direction dir) const noexcept {
  return dir == Direction::In ? in_.size() : out_.size();
}

FrameStatus FrameParser::feed(Direction dir, const std::uint8_t* data, std::size_t len,
                              std::vector<Frame>& out) {
  std::vector<std::uint8_t>& buffer = bufferFor(dir);
  if (data != nullptr && len > 0) {
    buffer.insert(buffer.end(), data, data + len);
  }

  std::size_t consumed = 0;
  // Bu çağrıda en az bir çerçeve üretildiyse Ok döner; resync olduysa ve
  // çerçeve de üretildiyse Ok baskındır, bilgi kaybı olmasın.
  bool produced = false;
  bool resynced = false;

  // Parser en az 7 bayt ister (sihir 2 + uzunluk 2 + kuyruk 2 + en az 1 gövde).
  while (buffer.size() - consumed >= kMinFrameBytes) {
    const std::uint8_t* cursor = buffer.data() + consumed;

    if (!hasMagic(cursor)) {
      // Sihir hatası: 2 bayt sola kaydır ve yeniden dene.
      consumed += kFrameMagicBytes;
      resynced = true;
      continue;
    }

    const std::size_t declared = readLength(cursor + kFrameMagicBytes);

    // Uzunluk, tamamlanmış bir çerçevenin sığabileceği üst sınırı aşarsa akış
    // güvenilmez; o yönün tamponu sıfırlanır.
    if (declared + kMinFrameBytes > maxBufferedBytes_) {
      buffer.clear();
      return FrameStatus::Overflow;
    }

    // Tam çerçeve henüz gelmediyse tamponda bekle.
    if (buffer.size() - consumed < declared + kMinFrameBytes) {
      break;
    }

    const std::uint8_t* trailer = cursor + kFrameHeaderBytes + declared;
    if (!hasTrailer(trailer)) {
      // Kuyruk hatası: sihir doğruydu ama çerçeve bozuk, 2 bayt kaydır.
      consumed += kFrameMagicBytes;
      resynced = true;
      continue;
    }

    Frame frame;
    frame.raw.assign(cursor, cursor + declared + kMinFrameBytes);
    frame.body.assign(cursor + kFrameHeaderBytes, trailer);
    out.push_back(std::move(frame));
    produced = true;
    consumed += declared + kMinFrameBytes;
  }

  if (consumed > 0) {
    buffer.erase(buffer.begin(),
                 buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
  }

  // Kalan tampon hâlâ sınırın üstündeyse (art arda gelen NeedMore durumları)
  // taşma sayılır; aksi halde bellek sınırsız büyür.
  if (buffer.size() > maxBufferedBytes_) {
    buffer.clear();
    return FrameStatus::Overflow;
  }

  if (produced) return FrameStatus::Ok;
  if (resynced) return FrameStatus::Resynced;
  return FrameStatus::NeedMore;
}

}  // namespace ko
