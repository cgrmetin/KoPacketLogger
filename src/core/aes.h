#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ko {

// AES-128 blok boyu ve anahtar boyu sabittir.
constexpr std::size_t kAesBlockSize = 16;
using Aes128Key = std::array<std::uint8_t, kAesBlockSize>;

// Protokolde sabit kodlanmis IV. CBC oldugu icin IV sabitse ayni duz metin
// ayni sifreli metni uretir; bu bilinen bir zayiflik, protokol boyle.
inline constexpr std::array<std::uint8_t, 16> kFixedIv{
    0x32, 0x4E, 0xAA, 0x58, 0xBC, 0xB3, 0xAE, 0xE3,
    0x6B, 0xC7, 0x4C, 0x56, 0x36, 0x47, 0x34, 0xF2};

// Sabit "private" (server) anahtari. Client anahtari handshake'ten gelir.
inline constexpr std::array<std::uint8_t, 16> kServerKey{
    0x87, 0x1F, 0xE5, 0x23, 0x78, 0xA1, 0x88, 0xAD,
    0x22, 0xCF, 0x5E, 0xAA, 0x5B, 0x18, 0x1E, 0x67};

enum class AesStatus {
  Ok,
  NullInput,
  NotBlockAligned,
  InvalidPadding,
  EmptyInput,
};

// Durum kodunun okunabilir adi; hata mesajlarinda kullanilir.
const char* aesStatusName(AesStatus status) noexcept;

// 32 karakterlik hex metni 16 byte anahtara cevirir. Uzunluk veya karakter
// hatasinda false doner ve `out` degismez.
bool parseHexKey(const std::string& hex, Aes128Key& out) noexcept;

// Byte dizisini buyuk harf hex metnine cevirir (gunluk/teshis icin).
std::string toHex(const std::uint8_t* data, std::size_t len);

// AES-128-CBC cozer, PKCS7 dolgusunu dogrular ve kaldirir.
// cipherLen 16&apos;nin kati olmali; sifir uzunluk EmptyInput, yanlis dolgu
// InvalidPadding olarak doner ve `plainOut` temizlenir.
AesStatus aes128CbcDecrypt(const Aes128Key& key, const std::uint8_t iv[kAesBlockSize],
                           const std::uint8_t* cipher, std::size_t cipherLen,
                           std::vector<std::uint8_t>& plainOut) noexcept;

// Tek blok AES-128 sifreleme (test vektorleri ve teshis icin).
void aes128EncryptBlock(const Aes128Key& key, const std::uint8_t in[kAesBlockSize],
                        std::uint8_t out[kAesBlockSize]) noexcept;

// Tek blok AES-128 cozme (test vektorleri ve teshis icin).
void aes128DecryptBlock(const Aes128Key& key, const std::uint8_t in[kAesBlockSize],
                        std::uint8_t out[kAesBlockSize]) noexcept;

} // namespace ko
