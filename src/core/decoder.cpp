#include "core/decoder.h"

#include <algorithm>
#include <cstddef>
#include <utility>

#include "core/opcodes.h"

namespace ko {
namespace {

// Anahtar secicileri (0x707ce8 oturum, 0x707d0e sabit).
constexpr std::uint8_t kSelectorSession = 1;
constexpr std::uint8_t kSelectorConstant = 2;

// Handshake govdesi (0x7BD730, IDA ile birebir dogrulandi):
//   [0]    0x2B opcode
//   [1]    PvP bayragi (0x7bd787)
//   [2..3] port u16 LE (0x7bd994)
//   [4]    anahtar uzunlugu (0x7bd9aa)
//   [5..]  HAM anahtar baytlari (0x7bd9e5)
constexpr std::uint8_t kHandshakeOpcode = 0x2B;
constexpr std::size_t kHandshakeHeaderBytes = 5;

// Sifreli cerceve isareti: cozulmus duz metin bununla baslarsa ilk 5 bayt atilir.
constexpr std::uint8_t kCryptMark0 = 0xFC;
constexpr std::uint8_t kCryptMark1 = 0x1E;
constexpr std::size_t kCryptMarkSkip = 5;

// Govde boyut kurali (0x707cd5): secici dahil uzunluk 16k+1 ve en az 17 olmali.
constexpr std::size_t kMinEncryptedBody = 17;

DecodedPacket fail(const RawPacket& raw, std::string message) {
  DecodedPacket result;
  result.raw = raw;
  result.ok = false;
  result.error = std::move(message);
  return result;
}

AesKey constantKey() noexcept {
  AesKey key;
  std::copy(kConstantKey.begin(), kConstantKey.end(), key.bytes.begin());
  key.len = kConstantKey.size();
  return key;
}

}  // namespace

bool Decoder::looksEncrypted(const std::vector<std::uint8_t>& body) noexcept {
  if (body.size() < kMinEncryptedBody) return false;
  const std::uint8_t selector = body[0];
  if (selector != kSelectorSession && selector != kSelectorConstant) return false;
  // Duz moddaki 0x01/0x02 opcode'lu paketler bu boyut kuralini gecemez.
  return (body.size() & 0xF) == 1;
}

const AesKey* Decoder::keyFor(std::uint8_t selector) const noexcept {
  static const AesKey kConstant = constantKey();
  switch (selector) {
    case kSelectorSession: return sessionKey_.valid() ? &sessionKey_ : nullptr;
    case kSelectorConstant: return &kConstant;
    default: return nullptr;
  }
}

void Decoder::reset() noexcept {
  sessionKey_ = AesKey{};
  encryptionEnabled_ = false;
  seqCounter_ = 0;
}

std::uint8_t Decoder::nextSeq() noexcept {
  if (!encryptionEnabled_ || !sessionKey_.valid()) return 0;
  if (++seqCounter_ > 0xFA) seqCounter_ = 1;
  return seqCounter_;
}

bool Decoder::captureSessionKey(const std::vector<std::uint8_t>& body,
                                std::string& error) {
  if (body.size() < kHandshakeHeaderBytes) {
    error = "handshake body too short for header";
    return false;
  }
  if (body[0] != kHandshakeOpcode) {
    error = "handshake body does not start with opcode 0x2B";
    return false;
  }

  const std::size_t keyLen = body[4];
  if (keyLen != kAesMinKeyBytes && keyLen != 24 && keyLen != kAesMaxKeyBytes) {
    error = "handshake key length is not 16/24/32";
    return false;
  }
  if (body.size() < kHandshakeHeaderBytes + keyLen) {
    error = "handshake body truncated before key bytes";
    return false;
  }

  AesKey key;
  std::copy(body.begin() + static_cast<std::ptrdiff_t>(kHandshakeHeaderBytes),
            body.begin() + static_cast<std::ptrdiff_t>(kHandshakeHeaderBytes + keyLen),
            key.bytes.begin());
  key.len = keyLen;

  sessionKey_ = key;
  // Anahtar geldiyse sifreleme acilir (0x7bd9d8: byte_1129B34 = v14 != 0).
  encryptionEnabled_ = true;
  // Sira sayaci sifirlanir (0x7bda8a).
  seqCounter_ = 0;
  return true;
}

DecodedPacket Decoder::decode(const RawPacket& raw) {
  const std::vector<std::uint8_t>& body = raw.data;

  if (body.empty()) return fail(raw, "empty frame body");

  // 1) Sifresiz mod: handshake ve sifreleme kapaliyken govde duzdur.
  const bool encrypted = encryptionEnabled_ && looksEncrypted(body);

  if (!encrypted) {
    DecodedPacket result;
    result.raw = raw;
    result.cryption = Cryption::Unknown;

    // Sifreleme kapaliyken de gelen handshake anahtari yakalanir.
    if (raw.dir == Direction::In && body[0] == kHandshakeOpcode) {
      std::string error;
      if (!captureSessionKey(body, error)) {
        result.error = error;
        return result;
      }
    }

    result.plain = body;
    result.opcode = result.plain[0];
    result.opcode_name = opcodeName(result.opcode);
    result.ok = true;
    return result;
  }

  // 2) Sifreli mod.
  DecodedPacket result;
  result.raw = raw;

  const std::uint8_t selector = body[0];
  const AesKey* key = keyFor(selector);
  if (key == nullptr) {
    if (selector == kSelectorSession) {
      result.error = "session selector but no session key captured";
    } else {
      result.error = "unknown key selector";
    }
    return result;
  }
  result.cryption =
      selector == kSelectorSession ? Cryption::Session : Cryption::Constant;

  const std::uint8_t* cipher = body.data() + 1;
  const std::size_t cipherLen = body.size() - 1;

  std::vector<std::uint8_t> plain;
  const AesStatus status =
      aesCbcDecrypt(*key, kFixedIv.data(), cipher, cipherLen, plain);
  if (status != AesStatus::Ok) {
    result.error = std::string("decrypt failed: ") + aesStatusName(status);
    return result;
  }
  if (plain.empty()) {
    result.error = "decrypt produced empty plaintext";
    return result;
  }

  // 3) Sira bayti yalnizca giden yonde vardir; once o ayiklanir.
  std::size_t offset = 0;
  if (raw.dir == Direction::Out) {
    result.seq = plain[0];
    offset = 1;
    if (plain.size() <= offset) {
      result.error = "plaintext too short for opcode after sequence byte";
      return result;
    }
  }

  // 4) Sifreli cerceve isareti (0x8e327a) kirpilir.
  if (plain.size() >= offset + 2 && plain[offset] == kCryptMark0 &&
      plain[offset + 1] == kCryptMark1) {
    offset += kCryptMarkSkip;
    if (plain.size() < offset) {
      result.error = "plaintext too short for crypt mark";
      return result;
    }
  }

  if (plain.size() <= offset) {
    result.error = "plaintext too short for opcode";
    return result;
  }

  result.opcode = plain[offset];
  result.opcode_name = opcodeName(result.opcode);
  result.plain.assign(plain.begin() + static_cast<std::ptrdiff_t>(offset), plain.end());
  result.ok = true;
  return result;
}

DecodedPacket Decoder::decode(Direction dir, std::int64_t tsUnixUs,
                              const std::vector<std::uint8_t>& body) {
  RawPacket raw;
  raw.ts_unix_us = tsUnixUs;
  raw.dir = dir;
  raw.data = body;
  return decode(raw);
}

}  // namespace ko
