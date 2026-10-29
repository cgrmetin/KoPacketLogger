#include "core/decoder.h"

#include <cstddef>

#include "core/opcodes.h"

namespace ko {
namespace {

// Handshake gövdesi: 0x16 0x00 0x2b öneki + 4 byte dolgu, ardından 32 karakter hex
// anahtar ve 1 byte kuyruk. Legacy kod payload üzerinden 7 byte atlayıp son byte'ı
// kırpıyordu; gövde payload[3]'ten başladığı için buradaki kayma 4 byte'tır.
constexpr std::uint8_t kHandshake0 = 0x16;
constexpr std::uint8_t kHandshake1 = 0x00;
constexpr std::uint8_t kHandshake2 = 0x2b;
constexpr std::size_t kHandshakeKeyOffset = 4;
constexpr std::size_t kHandshakeKeyChars = 32;

DecodedPacket fail(const RawPacket& raw, const char* message) {
  DecodedPacket result;
  result.raw = raw;
  result.ok = false;
  result.error = message;
  return result;
}

}  // namespace

const char* keyStateName(KeyState state) noexcept {
  switch (state) {
    case KeyState::NoClientKey: return "no client key";
    case KeyState::HaveClientKey: return "have client key";
  }
  return "unknown";
}

void Decoder::reset() noexcept {
  keyState_ = KeyState::NoClientKey;
  clientKey_.fill(0);
}

bool Decoder::tryCaptureClientKey(const std::vector<std::uint8_t>& body, std::string& error) {
  if (body.size() < kHandshakeKeyOffset + kHandshakeKeyChars) {
    error = "handshake frame too short for a 32 character key";
    return false;
  }

  const std::size_t end = body.size() - 1;  // kuyruk byte'ı kırpılır
  const std::size_t available = end - kHandshakeKeyOffset;
  if (available < kHandshakeKeyChars) {
    error = "handshake frame truncated";
    return false;
  }

  // Anahtar ASCII hex olarak taşınıyor; sadece ilk 32 karakter alınır.
  std::string hex;
  hex.reserve(kHandshakeKeyChars);
  for (std::size_t i = 0; i < kHandshakeKeyChars; ++i) {
    const std::uint8_t c = body[kHandshakeKeyOffset + i];
    if (c == 0) {
      error = "handshake key contains NUL";
      return false;
    }
    hex.push_back(static_cast<char>(c));
  }

  Aes128Key parsed{};
  if (!parseHexKey(hex, parsed)) {
    error = "handshake key is not valid hex";
    return false;
  }

  clientKey_ = parsed;
  keyState_ = KeyState::HaveClientKey;
  return true;
}

DecodedPacket Decoder::decode(const RawPacket& raw) {
  DecodedPacket result;
  result.raw = raw;

  const std::vector<std::uint8_t>& bytes = raw.data;
  if (bytes.size() < kMinFrameBytes) {
    result.error = "frame shorter than minimum frame size";
    return result;
  }

  const std::size_t declared = (static_cast<std::size_t>(bytes[0]) << 8) | bytes[1];
  if (declared != bytes.size()) {
    result.error = "declared length does not match frame size";
    return result;
  }

  const std::uint8_t cryptionByte = bytes[kFrameLengthBytes];
  const std::size_t bodyStart = kFrameHeaderBytes;
  const std::size_t bodyEnd = declared - kFrameTrailerBytes;
  const std::vector<std::uint8_t> body(bytes.begin() + static_cast<std::ptrdiff_t>(bodyStart),
                                       bytes.begin() + static_cast<std::ptrdiff_t>(bodyEnd));

  // Handshake: gövde açık metindir ve client anahtarını taşır.
  if (cryptionByte == kCryptionHandshake) {
    if (body.size() >= 3 && body[0] == kHandshake0 && body[1] == kHandshake1 &&
        body[2] == kHandshake2) {
      std::string error;
      if (!tryCaptureClientKey(body, error)) {
        result.error = error;
        return result;
      }
    }
    result.cryption = Cryption::Unknown;
    result.plain = body;
    result.ok = true;
    // Handshake'in kendi opcode'u yok; 0x16 sabiti taşınır, tabloda WIZ_REQ_USERIN'dir.
    result.opcode = kHandshake0;
    result.opcode_name = "HANDSHAKE";
    return result;
  }

  if (cryptionByte == kCryptionClient) {
    result.cryption = Cryption::Client;
  } else if (cryptionByte == kCryptionServer) {
    result.cryption = Cryption::Server;
  } else {
    result.error = "unknown cryption type byte";
    return result;
  }

  // Client çerçevesi için anahtar handshake'ten gelmiş olmalı.
  const Aes128Key* key = nullptr;
  if (result.cryption == Cryption::Client) {
    if (keyState_ != KeyState::HaveClientKey) {
      result.error = "client key not captured yet";
      return result;
    }
    key = &clientKey_;
  } else {
    key = &kServerKey;
  }

  if (body.empty()) {
    result.error = "empty frame body";
    return result;
  }

  std::vector<std::uint8_t> plain;
  const AesStatus status =
      aes128CbcDecrypt(*key, kFixedIv.data(), body.data(), body.size(), plain);
  if (status != AesStatus::Ok) {
    result.error = std::string("decrypt failed: ") + aesStatusName(status);
    return result;
  }
  if (plain.empty()) {
    result.error = "decrypt produced empty plaintext";
    return result;
  }

  // TODO(IDA): opcode konumu yöne göre kayıyor varsayımı doğrulanacak.
  // Gelen pakette plain[0], giden pakette plain[1] opcode kabul edilir.
  const std::size_t opcodeIndex = raw.dir == Direction::In ? 0 : 1;
  if (plain.size() <= opcodeIndex) {
    result.error = "plaintext too short for opcode";
    return result;
  }

  result.plain = std::move(plain);
  result.opcode = result.plain[opcodeIndex];
  result.opcode_name = opcodeName(result.opcode);
  result.ok = true;
  return result;
}

DecodedPacket Decoder::decode(Direction dir, std::int64_t tsUnixUs,
                              const std::vector<std::uint8_t>& frameBytes) {
  RawPacket raw;
  raw.ts_unix_us = tsUnixUs;
  raw.dir = dir;
  raw.data = frameBytes;
  return decode(raw);
}

}  // namespace ko
