#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/types.h"

namespace ko {

// Çerçeve biçimi (legacy C# kodunun varsayımı, IDA ile doğrulanacak):
//   [0..1] uzunluk (big-endian, çerçevenin TAMAMENIN byte cinsinden boyu)
//   [2]    kripto türü: 0x01 client, 0x02 server
//   [3..L-2) gövde (şifreli)
//   [L-2..L) legacy kodun atladığı 2 byte kuyruk (CRC/ayırıcı olduğu sanılıyor)
inline constexpr std::size_t kFrameLengthBytes = 2;
inline constexpr std::size_t kFrameCryptionBytes = 1;
inline constexpr std::size_t kFrameHeaderBytes = kFrameLengthBytes + kFrameCryptionBytes;
inline constexpr std::size_t kFrameTrailerBytes = 2;
inline constexpr std::size_t kMinFrameBytes = kFrameHeaderBytes + kFrameTrailerBytes;

// Kripto türü byte değerleri.
inline constexpr std::uint8_t kCryptionClient = 0x01;
inline constexpr std::uint8_t kCryptionServer = 0x02;
// 0x16 el sıkışma çerçevesidir: gövdesi şifreli değildir, client anahtarını taşır.
// Cryption enum'u sözleşme gereği üç değerli olduğu için Unknown olarak işaretlenir;
// ayrım raw byte'tan yapılır.
inline constexpr std::uint8_t kCryptionHandshake = 0x16;

enum class FrameStatus {
  NeedMore,     // elimizde tam çerçeve yok, daha fazla byte gerekli
  Ok,           // en az bir çerçeve üretildi
  BadLength,    // uzunluk alanı geçersiz, o yönün tamponu sıfırlandı
  BadCryption,  // kripto türü tanınmadı, çerçeve atlandı
  Overflow,     // tampon üst sınırı aşıldı, o yönün tamponu sıfırlandı
};

const char* frameStatusName(FrameStatus status) noexcept;

struct Frame {
  Cryption cryption = Cryption::Unknown;
  // Ham kripto türü byte'ı; 0x16 handshake için Cryption::Unknown olur, bu yüzden ayrı tutulur.
  std::uint8_t cryption_byte = 0;
  std::vector<std::uint8_t> body;
  // Çerçevenin ham byte'ları (başlık ve kuyruk dahil), teşhis için.
  std::vector<std::uint8_t> raw;
};

// Yön başına ayrı akış tamponu tutan, TCP segment birleşmesini yapan ayrıştırıcı.
// Tek iş parçacığından kullanılır; iç eşitleme yok.
class FrameParser {
 public:
  explicit FrameParser(std::size_t maxFrameBytes = 0xFFFF, std::size_t maxBufferedBytes = 1u << 20);

  // Gelen byte'ları ilgili yönün tamponuna ekler ve tamamlanan çerçeveleri `out`a
  // yazar. Bir hata durumunda o yönün tamponu sıfırlanır, `out` o ana kadarki
  // çerçeveleri korur ve hata durumu döner.
  FrameStatus feed(Direction dir, const std::uint8_t* data, std::size_t len,
                   std::vector<Frame>& out);

  // Bir yönün tamponunu boşaltır (bağlantı yeniden kurulduğunda çağrılır).
  void reset(Direction dir) noexcept;
  void resetAll() noexcept;

  // Test/teşhis için tampon durumu.
  std::size_t buffered(Direction dir) const noexcept;

 private:
  std::vector<std::uint8_t>& bufferFor(Direction dir) noexcept;

  std::vector<std::uint8_t> in_;
  std::vector<std::uint8_t> out_;
  std::size_t maxFrameBytes_;
  std::size_t maxBufferedBytes_;
};

}  // namespace ko
