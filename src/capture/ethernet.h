#pragma once

#include <cstddef>
#include <cstdint>

#include "core/types.h"

namespace ko::net {

// pcap link tipi; çerçevenin hangi katmandan başladığını belirler.
enum class LinkType {
  Ethernet,  // DLT_EN10MB: Ethernet II, VLAN etiketleri atlanır
  RawIp,     // DLT_RAW: çerçeve doğrudan IP başlığıyla başlar (WARP, tüneller)
  NullLoop,  // DLT_NULL / DLT_LOOP: başta 4 byte adres ailesi alanı
};

// Çözülen çerçeve: TCP payload'ı ve trafik yönü.
struct ParsedFrame {
  const std::uint8_t* payload = nullptr;
  std::size_t payload_len = 0;
  Direction dir = Direction::Out;
};

// Ham çerçeveyi link tipine göre çözer: (Ethernet/VLAN) -> IPv4/IPv6 -> TCP.
// Sadece payload'ı sıfırdan büyük ve portları hedef aralıkta olan çerçeveler için true döner.
// Sınır kontrolleri içeridedir; bozuk/kısa/parçalı çerçevede false döner, istisna atmaz.
bool parseFrame(const std::uint8_t* frame, std::size_t len, ParsedFrame& out,
                LinkType link = LinkType::Ethernet) noexcept;

// Hedef port dinlenen aralıkta mı (Out yönü).
bool isTargetPort(std::uint16_t port) noexcept;

}  // namespace ko::net
