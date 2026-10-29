#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ko {

// Doğrulanmış kripto katmanı (IDA: aes_crypt_cbc @ 0x707C60, aes_key_schedule @ 0x708B00).
//
// - AES-CBC, PKCS#7 dolgu.
// - IV HER ZAMAN sabittir (0x707d7e: xmmword_1013FC8), paketten gelmez.
// - Anahtar uzunluğu 16/24/32 -> AES-128/192/256 (Nk=4/6/8, Nr=10/12/14).
// - Anahtar ASCII hex değil HAM bayttır (0x7bd9e5: sub_5EFAB0 ile kopya).

constexpr std::size_t kAesBlockSize = 16;
constexpr std::size_t kAesMaxKeyBytes = 32;
constexpr std::size_t kAesMinKeyBytes = 16;

// Sabit IV. CBC olduğu için aynı düz metin aynı şifreli metni üretir; protokol böyle.
inline constexpr std::array<std::uint8_t, kAesBlockSize> kFixedIv{
    0x32, 0x4E, 0xAA, 0x58, 0xBC, 0xB3, 0xAE, 0xE3,
    0x6B, 0xC7, 0x4C, 0x56, 0x36, 0x47, 0x34, 0xF2};

// Anahtar seçici 2&apos;nin kullandığı gömülü sabit anahtar (0x707d0e:
// 0xAD88A17823E51F87 / 0x671E185BAA5ECF22, AES-128).
inline constexpr std::array<std::uint8_t, kAesBlockSize> kConstantKey{
    0x87, 0x1F, 0xE5, 0x23, 0x78, 0xA1, 0x88, 0xAD,
    0x22, 0xCF, 0x5E, 0xAA, 0x5B, 0x18, 0x1E, 0x67};

// Değişken uzunluklu anahtar. `len` 16/24/32 dışındaysa geçersizdir.
struct AesKey {
  std::array<std::uint8_t, kAesMaxKeyBytes> bytes{};
  std::size_t len = 0;

  bool valid() const noexcept {
    return len == 16 || len == 24 || len == 32;
  }
};

// Sözleşme uyumu için eski 16 baytlık sabit boy tip korunuyor.
using Aes128Key = std::array<std::uint8_t, kAesBlockSize>;

enum class AesStatus {
  Ok,
  NullInput,
  EmptyInput,
  BadKeyLength,
  NotBlockAligned,
  InvalidPadding,
};

const char* aesStatusName(AesStatus status) noexcept;

// 32 karakterlik hex metni 16 baytlık anahtara çevirir. Yalnızca teşhis ve test
// içindir; protokoldeki handshake anahtarı hex değildir.
bool parseHexKey(const std::string& hex, Aes128Key& out) noexcept;

// Bayt dizisini büyük harf hex metnine çevirir (günlük/teşhis için).
std::string toHex(const std::uint8_t* data, std::size_t len);

// Tek blok şifreleme/çözme; FIPS-197 vektörleri için genel anahtar boyu destekler.
AesStatus aesEncryptBlock(const AesKey& key, const std::uint8_t in[kAesBlockSize],
                          std::uint8_t out[kAesBlockSize]) noexcept;
AesStatus aesDecryptBlock(const AesKey& key, const std::uint8_t in[kAesBlockSize],
                          std::uint8_t out[kAesBlockSize]) noexcept;

// AES-CBC + PKCS#7. `out` her zaman temizlenir; hata durumunda boş kalır.
// Girdi uzunluğu 16&apos;nın katı olmalı ve sıfırdan büyük olmalıdır.
AesStatus aesCbcEncrypt(const AesKey& key, const std::uint8_t iv[kAesBlockSize],
                        const std::uint8_t* data, std::size_t len,
                        std::vector<std::uint8_t>& out) noexcept;
AesStatus aesCbcDecrypt(const AesKey& key, const std::uint8_t iv[kAesBlockSize],
                        const std::uint8_t* cipher, std::size_t cipherLen,
                        std::vector<std::uint8_t>& plainOut) noexcept;

}  // namespace ko
