#include "core/frame.h"

#include <algorithm>
#include <cstring>

namespace ko {
namespace {

// Büyük-endian 16 bit uzunluk okur.
std::size_t readLength(const std::uint8_t* p) noexcept {
  return (static_cast<std::size_t>(p[0]) << 8) | static_cast<std::size_t>(p[1]);
}

Cryption toCryption(std::uint8_t raw) noexcept {
  switch (raw) {
    case kCryptionClient: return Cryption::Client;
    case kCryptionServer: return Cryption::Server;
    default: return Cryption::Unknown;
  }
}

// 0x16 handshake çerçevesi geçerlidir ama Cryption enum&apos;unda karşılığı yoktur.
bool isKnownCryptionByte(std::uint8_t raw) noexcept {
  return raw == kCryptionClient || raw == kCryptionServer || raw == kCryptionHandshake;
}

}  // namespace

const char* frameStatusName(FrameStatus status) noexcept {
  switch (status) {
    case FrameStatus::NeedMore: return "need more bytes";
    case FrameStatus::Ok: return "ok";
    case FrameStatus::BadLength: return "bad frame length";
    case FrameStatus::BadCryption: return "unknown cryption type";
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
  FrameStatus status = FrameStatus::NeedMore;

  while (buffer.size() - consumed >= kFrameLengthBytes) {
    const std::size_t declared = readLength(buffer.data() + consumed);

    // Uzunluk, çerçeve başlığından küçükse akış güvenilmez; yönü sıfırla.
    if (declared < kMinFrameBytes || declared > maxFrameBytes_) {
      status = FrameStatus::BadLength;
      consumed = buffer.size();
      break;
    }

    // Uzunluk tampon sınırını aşacaksa (ve zaten aşılmışsa) sıfırla.
    if (declared > maxBufferedBytes_) {
      status = FrameStatus::Overflow;
      consumed = buffer.size();
      break;
    }

    // Tam çerçeve henüz gelmediyse bekle, tampon üst sınırını kontrol et.
    if (buffer.size() - consumed < declared) {
      if (buffer.size() > maxBufferedBytes_) {
        status = FrameStatus::Overflow;
        consumed = buffer.size();
      }
      break;
    }

    const std::uint8_t* framePtr = buffer.data() + consumed;
    const std::uint8_t cryptionByte = framePtr[kFrameLengthBytes];
    if (!isKnownCryptionByte(cryptionByte)) {
      // Kripto türü tanınmadı: uzunluk doğruysa çerçeveyi atla, akışı bozmadan devam et.
      consumed += declared;
      if (status != FrameStatus::Ok) status = FrameStatus::BadCryption;
      continue;
    }

    Frame frame;
    frame.cryption = toCryption(cryptionByte);
    frame.cryption_byte = cryptionByte;
    frame.raw.assign(framePtr, framePtr + declared);

    const std::size_t bodyStart = kFrameHeaderBytes;
    const std::size_t bodyEnd = declared - kFrameTrailerBytes;
    frame.body.assign(framePtr + bodyStart, framePtr + bodyEnd);

    out.push_back(std::move(frame));
    consumed += declared;
    status = FrameStatus::Ok;
  }

  if (consumed > 0) {
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
  }

  // Hata sonrası tampon boşaltıldı; sonraki çağrı temiz başlar.
  if (status == FrameStatus::BadLength || status == FrameStatus::Overflow) {
    buffer.clear();
  }

  return status;
}

}  // namespace ko
