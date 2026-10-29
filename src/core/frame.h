#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/types.h"

namespace ko {

// Doğrulanmış çerçeve biçimi (IDA: pkt_parse_frames @ 0x70C0E0):
//   [0..1]  sihir 0xAA55  -> kablo üzerinde AA 55
//   [2..3]  gövde uzunluğu, uint16 LITTLE-ENDIAN
//   [4..4+len)  gövde
//   [len+4..len+6) kuyruk 0x55AA -> kablo üzerinde 55 AA
// Toplam çerçeve boyu len + 6. Parser en az 7 bayt ister (0x70c176: cmp esi,7 / jl).
//
// Şifreleme bayrağı başlıkta DEĞİLDİR; gövdenin ilk baytı anahtar seçicidir ve
// karar Decoder içinde verilir. Çerçeve katmanı gövdeyi yalnızca sınırlar.
//
// Sihir veya kuyruk uyuşmazsa akış 2 bayt sola kaydırılıp yeniden senkronize
// edilir (0x70c27c, 0x70c282). Eksik segment tamponda bekletilir.
inline constexpr std::size_t kFrameMagicBytes = 2;
inline constexpr std::size_t kFrameLengthBytes = 2;
inline constexpr std::size_t kFrameHeaderBytes = kFrameMagicBytes + kFrameLengthBytes;
inline constexpr std::size_t kFrameTrailerBytes = 2;
// Sihir + uzunluk + kuyruk; gövdesiz en küçük geçerli çerçeve.
inline constexpr std::size_t kMinFrameBytes = kFrameHeaderBytes + kFrameTrailerBytes;

// Kablo üzerindeki sabitler, okundukları bayt sırasıyla.
inline constexpr std::uint16_t kFrameMagicWire = 0x55AA;   // bellek: AA 55
inline constexpr std::uint16_t kFrameTrailerWire = 0xAA55;  // bellek: 55 AA

enum class FrameStatus {
  NeedMore,   // elimizde tam çerçeve yok, daha fazla bayt gerekli
  Ok,         // en az bir çerçeve üretildi
  Resynced,   // sihir/kuyruk hatası görüldü, 2 bayt kaydırılıp devam edildi
  Overflow,   // tampon üst sınırı aşıldı, o yönün tamponu sıfırlandı
};

const char* frameStatusName(FrameStatus status) noexcept;

struct Frame {
  std::vector<std::uint8_t> body;
  // Çerçevenin ham baytları (başlık ve kuyruk dahil), teşhis için.
  std::vector<std::uint8_t> raw;
};

// Yön başına ayrı akış tamponu tutan, TCP segment birleşmesini yapan ayrıştırıcı.
// Tek iş parçacığından kullanılır; iç eşitleme yok.
class FrameParser {
 public:
  explicit FrameParser(std::size_t maxFrameBytes = 0xFFFF,
                       std::size_t maxBufferedBytes = 1u << 20);

  // Gelen baytları ilgili yönün tamponuna ekler ve tamamlanan çerçeveleri `out`a
  // yazar. Hata durumunda o yönün tamponu sıfırlanır, `out` o ana kadarki
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
