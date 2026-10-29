#include "core/aes.h"

#include <array>
#include <cstring>

namespace ko {
namespace {

// AES-128 sabitleri. Nk=4 (128 bit anahtar), Nr=10 tur.
constexpr std::size_t kRounds = 10;
constexpr std::size_t kKeyBytes = 16;
constexpr std::size_t kRoundKeyBytes = 16 * (kRounds + 1);

constexpr std::array<std::uint8_t, 256> kSbox{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

constexpr std::array<std::uint8_t, 256> kInvSbox{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

constexpr std::array<std::uint8_t, 11> kRcon{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// GF(2^8) carpimi; xtime tablosu yerine dogrudan hesap, tablo boyu kucuk kalsin.
std::uint8_t gmul(std::uint8_t a, std::uint8_t b) noexcept {
  std::uint8_t result = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) result ^= a;
    const std::uint8_t high = static_cast<std::uint8_t>(a & 0x80);
    a = static_cast<std::uint8_t>(a << 1);
    if (high) a ^= 0x1b;
    b = static_cast<std::uint8_t>(b >> 1);
  }
  return result;
}

using RoundKeys = std::array<std::uint8_t, kRoundKeyBytes>;

// FIPS-197 anahtar genisletme. Tek blok cozme icin gerekli tur anahtarlarini uretir.
void expandKey(const Aes128Key& key, RoundKeys& roundKeys) noexcept {
  std::memcpy(roundKeys.data(), key.data(), kKeyBytes);

  for (std::size_t i = 4; i < 4 * (kRounds + 1); ++i) {
    std::array<std::uint8_t, 4> temp{
        roundKeys[(i - 1) * 4 + 0],
        roundKeys[(i - 1) * 4 + 1],
        roundKeys[(i - 1) * 4 + 2],
        roundKeys[(i - 1) * 4 + 3]};

    if (i % 4 == 0) {
      // RotWord + SubWord + Rcon
      const std::uint8_t t0 = temp[0];
      temp[0] = static_cast<std::uint8_t>(kSbox[temp[1]] ^ kRcon[i / 4]);
      temp[1] = kSbox[temp[2]];
      temp[2] = kSbox[temp[3]];
      temp[3] = kSbox[t0];
    }

    for (std::size_t j = 0; j < 4; ++j) {
      roundKeys[i * 4 + j] = static_cast<std::uint8_t>(roundKeys[(i - 4) * 4 + j] ^ temp[j]);
    }
  }
}

void addRoundKey(std::uint8_t state[16], const std::uint8_t* roundKey) noexcept {
  for (std::size_t i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

void invShiftRows(std::uint8_t s[16]) noexcept {
  std::uint8_t t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;

  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;

  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
}

void invSubBytes(std::uint8_t s[16]) noexcept {
  for (std::size_t i = 0; i < 16; ++i) s[i] = kInvSbox[s[i]];
}

void invMixColumns(std::uint8_t s[16]) noexcept {
  for (std::size_t c = 0; c < 4; ++c) {
    std::uint8_t* col = s + c * 4;
    const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = static_cast<std::uint8_t>(gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09));
    col[1] = static_cast<std::uint8_t>(gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d));
    col[2] = static_cast<std::uint8_t>(gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b));
    col[3] = static_cast<std::uint8_t>(gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e));
  }
}

void shiftRows(std::uint8_t s[16]) noexcept {
  std::uint8_t t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;

  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;

  t = s[3];
  s[3] = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = t;
}

void subBytes(std::uint8_t s[16]) noexcept {
  for (std::size_t i = 0; i < 16; ++i) s[i] = kSbox[s[i]];
}

void mixColumns(std::uint8_t s[16]) noexcept {
  for (std::size_t c = 0; c < 4; ++c) {
    std::uint8_t* col = s + c * 4;
    const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = static_cast<std::uint8_t>(gmul(a0, 0x02) ^ gmul(a1, 0x03) ^ a2 ^ a3);
    col[1] = static_cast<std::uint8_t>(a0 ^ gmul(a1, 0x02) ^ gmul(a2, 0x03) ^ a3);
    col[2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gmul(a2, 0x02) ^ gmul(a3, 0x03));
    col[3] = static_cast<std::uint8_t>(gmul(a0, 0x03) ^ a1 ^ a2 ^ gmul(a3, 0x02));
  }
}

int hexNibble(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

} // namespace

const char* aesStatusName(AesStatus status) noexcept {
  switch (status) {
    case AesStatus::Ok: return "ok";
    case AesStatus::NullInput: return "null input";
    case AesStatus::NotBlockAligned: return "cipher length not a multiple of 16";
    case AesStatus::InvalidPadding: return "invalid PKCS7 padding";
    case AesStatus::EmptyInput: return "empty cipher input";
  }
  return "unknown";
}

bool parseHexKey(const std::string& hex, Aes128Key& out) noexcept {
  if (hex.size() != kAesBlockSize * 2) return false;

  Aes128Key parsed{};
  for (std::size_t i = 0; i < kAesBlockSize; ++i) {
    const int hi = hexNibble(hex[i * 2]);
    const int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    parsed[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }

  out = parsed;
  return true;
}

std::string toHex(const std::uint8_t* data, std::size_t len) {
  static constexpr char kDigits[] = "0123456789ABCDEF";
  std::string result;
  if (data == nullptr) return result;
  result.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    result.push_back(kDigits[data[i] >> 4]);
    result.push_back(kDigits[data[i] & 0x0f]);
  }
  return result;
}

void aes128EncryptBlock(const Aes128Key& key, const std::uint8_t in[kAesBlockSize],
                        std::uint8_t out[kAesBlockSize]) noexcept {
  RoundKeys roundKeys{};
  expandKey(key, roundKeys);

  std::uint8_t state[16];
  std::memcpy(state, in, 16);

  addRoundKey(state, roundKeys.data());
  for (std::size_t round = 1; round < kRounds; ++round) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKeys.data() + round * 16);
  }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKeys.data() + kRounds * 16);

  std::memcpy(out, state, 16);
}

void aes128DecryptBlock(const Aes128Key& key, const std::uint8_t in[kAesBlockSize],
                        std::uint8_t out[kAesBlockSize]) noexcept {
  RoundKeys roundKeys{};
  expandKey(key, roundKeys);

  std::uint8_t state[16];
  std::memcpy(state, in, 16);

  addRoundKey(state, roundKeys.data() + kRounds * 16);
  for (std::size_t round = kRounds; round-- > 1;) {
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys.data() + round * 16);
    invMixColumns(state);
  }
  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, roundKeys.data());

  std::memcpy(out, state, 16);
}

AesStatus aes128CbcDecrypt(const Aes128Key& key, const std::uint8_t iv[kAesBlockSize],
                           const std::uint8_t* cipher, std::size_t cipherLen,
                           std::vector<std::uint8_t>& plainOut) noexcept {
  plainOut.clear();
  if (cipher == nullptr || iv == nullptr) return AesStatus::NullInput;
  if (cipherLen == 0) return AesStatus::EmptyInput;
  if (cipherLen % kAesBlockSize != 0) return AesStatus::NotBlockAligned;

  plainOut.resize(cipherLen);

  std::uint8_t previous[kAesBlockSize];
  std::memcpy(previous, iv, kAesBlockSize);

  for (std::size_t offset = 0; offset < cipherLen; offset += kAesBlockSize) {
    std::uint8_t decrypted[kAesBlockSize];
    aes128DecryptBlock(key, cipher + offset, decrypted);
    for (std::size_t i = 0; i < kAesBlockSize; ++i) {
      plainOut[offset + i] = static_cast<std::uint8_t>(decrypted[i] ^ previous[i]);
    }
    std::memcpy(previous, cipher + offset, kAesBlockSize);
  }

  // PKCS7 dolgu dogrulamasi: son byte 1..16, onceki pad byte&apos;lari ayni degerde.
  const std::uint8_t pad = plainOut.back();
  if (pad == 0 || pad > kAesBlockSize) {
    plainOut.clear();
    return AesStatus::InvalidPadding;
  }
  for (std::size_t i = 0; i < pad; ++i) {
    if (plainOut[plainOut.size() - 1 - i] != pad) {
      plainOut.clear();
      return AesStatus::InvalidPadding;
    }
  }

  plainOut.resize(plainOut.size() - pad);
  return AesStatus::Ok;
}

} // namespace ko
