#pragma once

#include <cstddef>
#include <cstdint>

#include "core/types.h"

namespace ko::net {

// pcap link tipi; çerçevenin hangi katmandan başladığını belirler.
enum class LinkType {
  Ethernet,    // DLT_EN10MB: Ethernet II, VLAN etiketleri atlanır
  RawIp,       // DLT_RAW: çerçeve doğrudan IP başlığıyla başlar (WARP, tüneller)
  NullLoop,    // DLT_NULL / DLT_LOOP: başta 4 byte adres ailesi alanı
  Dot11,       // DLT_IEEE802_11: ham 802.11 çerçevesi, LLC/SNAP sonrası IP
  Dot11Radio,  // DLT_IEEE802_11_RADIO: başta radiotap başlığı, sonra 802.11
};

// Çözülen çerçeve: TCP payload'ı ve trafik yönü.
struct ParsedFrame {
  const std::uint8_t* payload = nullptr;
  std::size_t payload_len = 0;
  Direction dir = Direction::Out;
  // false dönüşünün nedeni; sessiz atlama yerine teşhis için doldurulur.
  // Şifreli 802.11 gövdesi çözülemediğinde boş kalır (beklenen durum).
  const char* err = nullptr;
};

// Ham çerçeveyi link tipine göre çözer: (Ethernet/VLAN | radiotap+802.11 | NullLoop)
// -> IPv4/IPv6 -> TCP. 802.11'de yönetim/kontrol çerçeveleri reddedilir ve nedeni
// `out.err` ile bildirilir; şifreli gövde çözülemezse hata üretilmez.
// Sadece payload'ı sıfırdan büyük ve portları hedef aralıkta olan çerçeveler için true döner.
// Sınır kontrolleri içeridedir; bozuk/kısa/parçalı çerçevede false döner, istisna atmaz.
bool parseFrame(const std::uint8_t* frame, std::size_t len, ParsedFrame& out,
                LinkType link = LinkType::Ethernet) noexcept;

// Hedef port dinlenen aralıkta mı (Out yönü).
bool isTargetPort(std::uint16_t port) noexcept;

}  // namespace ko::net
