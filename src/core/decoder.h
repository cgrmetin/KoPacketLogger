#pragma once
#include <cstdint>
#include <string>

#include "core/aes.h"
#include "core/frame.h"
#include "core/types.h"

namespace ko {

// Anahtar durum makinesi. Client anahtarı yalnızca handshake çerçevesinden gelir;
// server anahtarı protokolde sabittir.
enum class KeyState {
  NoClientKey,  // henüz handshake görülmedi
  HaveClientKey,
};

const char* keyStateName(KeyState state) noexcept;

// RawPacket -> DecodedPacket.
//
// Sözleşme gereği girdi RawPacket'tır ve `data` alanı çerçevenin HAM byte'larını
// taşır (uzunluk + kripto türü + gövde + kuyruk). FrameParser'ın ürettiği
// Frame::raw doğrudan buraya verilebilir.
//
// Opcode konumu yöne göre kayıyor: gelen pakette plain[0], giden pakette plain[1].
// Bu legacy C# kodunun varsayımıdır, IDA ajanı doğrulayana kadar böyle kalacak.
//
// Tek iş parçacığından kullanılır; iç eşitleme yok.
class Decoder {
 public:
  Decoder() = default;

  // Çerçeveyi çözer. Hata durumunda `ok=false`, `error` dolu döner; sessiz yutma yok.
  DecodedPacket decode(const RawPacket& raw);

  // Kolaylık: ham bayt ve yön bilgisinden RawPacket kurup çözer.
  DecodedPacket decode(Direction dir, std::int64_t tsUnixUs,
                       const std::vector<std::uint8_t>& frameBytes);

  // Bağlantı yeniden kurulduğunda anahtar durumunu sıfırlar.
  void reset() noexcept;

  KeyState keyState() const noexcept { return keyState_; }
  bool hasClientKey() const noexcept { return keyState_ == KeyState::HaveClientKey; }

 private:
  // Handshake gövdesinden client anahtarını okur. Başarılıysa true.
  bool tryCaptureClientKey(const std::vector<std::uint8_t>& body, std::string& error);

  KeyState keyState_ = KeyState::NoClientKey;
  Aes128Key clientKey_{};
};

}  // namespace ko
