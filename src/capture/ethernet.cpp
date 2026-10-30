#include "capture/ethernet.h"

#include <cstdint>

namespace ko::net {
namespace {

// Çerçeve sabitleri (ağ bayt sırası).
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;
constexpr std::uint16_t kEtherTypeVlan9100 = 0x9100;
constexpr std::uint16_t kEtherTypeIPv4 = 0x0800;
constexpr std::uint16_t kEtherTypeIPv6 = 0x86DD;
constexpr std::uint8_t kProtoTCP = 6;

constexpr std::size_t kEtherHeaderLen = 14;
constexpr std::size_t kVlanTagLen = 4;
constexpr std::size_t kNullFamilyLen = 4;
constexpr std::size_t kIPv4MinHeaderLen = 20;
constexpr std::size_t kIPv6HeaderLen = 40;
constexpr std::size_t kTCPMinHeaderLen = 20;
constexpr std::size_t kMaxVlanTags = 3;

// 802.11 çerçeve sabitleri (frame control bitleri ve başlık uzunlukları).
constexpr std::uint8_t kDot11TypeData = 2;
constexpr std::uint8_t kDot11QosSubtypeBit = 0x08;  // veri alt tipinde QoS
constexpr std::uint8_t kDot11OrderBit = 0x80;       // HT kontrolü var
constexpr std::size_t kDot11FrameControlLen = 2;
constexpr std::size_t kDot11HeaderLen = 24;
constexpr std::size_t kDot11QosLen = 2;
constexpr std::size_t kDot11HtControlLen = 4;
constexpr std::size_t kSnapHeaderLen = 8;  // AA AA 03 + OUI 00 00 00 + EtherType

// Radiotap: sürüm(1) + pad(1) + it_len(2, LE) + present(4) en az 8 bayttır.
constexpr std::size_t kRadiotapMinLen = 8;
constexpr std::size_t kRadiotapLenOffset = 2;
constexpr std::uint8_t kRadiotapVersion = 0;

// Dinlenen port aralığı: 15100-15109 ve 15001.
constexpr std::uint16_t kPortLow = 15100;
constexpr std::uint16_t kPortHigh = 15109;
constexpr std::uint16_t kPortSingle = 15001;

inline std::uint16_t readBe16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

inline std::uint16_t readLe16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                    (static_cast<std::uint16_t>(p[1]) << 8));
}

// IPv6 uzantı başlığı mı? (yönlendirme, parça, hedef seçenekleri, AH)
inline bool isIPv6Extension(std::uint8_t next) noexcept {
  switch (next) {
    case 0:    // hop-by-hop
    case 43:   // routing
    case 44:   // fragment
    case 60:   // destination options
    case 51:   // authentication header
      return true;
    default:
      return false;
  }
}

// IPv6 uzantı zincirini atlar, TCP'ye ulaşınca true döner.
// Parçalı pakette ilk parça değilse (offset sıfır değil) false döner: yarım payload işlenmez.
bool walkIPv6Extensions(const std::uint8_t* frame, std::size_t len, std::size_t& off,
                        std::uint8_t& next) noexcept {
  int guard = 0;
  while (isIPv6Extension(next)) {
    if (++guard > 8) return false;
    if (off + 2 > len) return false;

    const std::uint8_t ext_next = frame[off];
    if (next == 44) {
      // Parça başlığı: 8 byte sabit, offset alanı üst 13 bit.
      if (off + 8 > len) return false;
      const std::uint16_t frag_field = readBe16(frame + off + 2);
      const bool more_fragments = (frag_field & 0x0001u) != 0;
      const std::uint16_t frag_offset = static_cast<std::uint16_t>(frag_field >> 3);
      if (frag_offset != 0 || more_fragments) return false;
      off += 8;
    } else if (next == 51) {
      // AH: uzunluk (32 bit sözcük) * 4 + 8.
      if (off + 2 > len) return false;
      const std::size_t ah_len = (static_cast<std::size_t>(frame[off + 1]) + 2) * 4;
      if (off + ah_len > len) return false;
      off += ah_len;
    } else {
      // Hop-by-hop / routing / dest options: uzunluk (8 oktev) * 8 + 8.
      if (off + 2 > len) return false;
      const std::size_t ext_len = (static_cast<std::size_t>(frame[off + 1]) + 1) * 8;
      if (off + ext_len > len) return false;
      off += ext_len;
    }
    next = ext_next;
  }
  return next == kProtoTCP;
}

// IPv4 başlığını atlar, TCP'ye işaret eder. Parçalı pakette ilk parça değilse false.
bool walkIPv4(const std::uint8_t* frame, std::size_t len, std::size_t off,
              std::size_t& tcp_off) noexcept {
  if (off + kIPv4MinHeaderLen > len) return false;
  if ((frame[off] >> 4) != 4) return false;

  const std::size_t ihl = static_cast<std::size_t>(frame[off] & 0x0Fu) * 4;
  if (ihl < kIPv4MinHeaderLen) return false;
  if (off + ihl > len) return false;
  if (frame[off + 9] != kProtoTCP) return false;

  const std::uint16_t frag_field = readBe16(frame + off + 6);
  const bool more_fragments = (frag_field & 0x2000u) != 0;
  const std::uint16_t frag_offset = static_cast<std::uint16_t>(frag_field & 0x1FFFu);
  if (frag_offset != 0 || more_fragments) return false;

  tcp_off = off + ihl;
  return true;
}

// IPv6 sabit başlığını ve uzantılarını atlar, TCP'ye işaret eder.
bool walkIPv6(const std::uint8_t* frame, std::size_t len, std::size_t off,
              std::size_t& tcp_off) noexcept {
  if (off + kIPv6HeaderLen > len) return false;
  if ((frame[off] >> 4) != 6) return false;

  std::uint8_t next = frame[off + 6];
  std::size_t cursor = off + kIPv6HeaderLen;
  if (!walkIPv6Extensions(frame, len, cursor, next)) return false;

  tcp_off = cursor;
  return true;
}

// IP sürüm nibble'ına göre IPv4/IPv6 ayrımı yapar.
bool walkIp(const std::uint8_t* frame, std::size_t len, std::size_t off,
            std::size_t& tcp_off) noexcept {
  if (off >= len) return false;
  const std::uint8_t version = static_cast<std::uint8_t>(frame[off] >> 4);
  if (version == 4) return walkIPv4(frame, len, off, tcp_off);
  if (version == 6) return walkIPv6(frame, len, off, tcp_off);
  return false;
}

// DLT_NULL / DLT_LOOP başlığındaki adres ailesi alanını atlar.
// Windows'ta küçük, BSD'de büyük bayt sırası olabilir; iki yorum da denenir.
bool skipNullFamily(const std::uint8_t* frame, std::size_t len, std::size_t& off) noexcept {
  if (len < kNullFamilyLen) return false;
  const std::uint32_t le = static_cast<std::uint32_t>(frame[0]) |
                           (static_cast<std::uint32_t>(frame[1]) << 8) |
                           (static_cast<std::uint32_t>(frame[2]) << 16) |
                           (static_cast<std::uint32_t>(frame[3]) << 24);
  const std::uint32_t be = (static_cast<std::uint32_t>(frame[0]) << 24) |
                           (static_cast<std::uint32_t>(frame[1]) << 16) |
                           (static_cast<std::uint32_t>(frame[2]) << 8) |
                           static_cast<std::uint32_t>(frame[3]);

  const bool ipv4 = le == 2 || be == 2;
  const bool ipv6 = le == 23 || le == 24 || le == 28 || le == 30 ||
                    be == 23 || be == 24 || be == 28 || be == 30;
  if (!ipv4 && !ipv6) return false;

  off += kNullFamilyLen;
  return true;
}


// EtherType ile IP sürüm nibble'ı uyuşmalı; aksi halde yanlış yorumlanır.
bool etherTypeMatchesIp(const std::uint8_t* frame, std::size_t len, std::size_t off,
                        std::uint16_t ether_type) noexcept {
  if (off >= len) return false;
  const std::uint8_t version = static_cast<std::uint8_t>(frame[off] >> 4);
  if (ether_type == kEtherTypeIPv4) return version == 4;
  if (ether_type == kEtherTypeIPv6) return version == 6;
  return false;
}

// 802.11 veri çerçevesini çözer: yönü frame control bitlerinden türetir, adres
// alanlarını ve LLC/SNAP başlığını atlayıp IP'ye işaret eder.
// Yönetim/kontrol çerçeveleri sessizce yutulmaz, `out.err` ile bildirilir.
bool walkDot11(const std::uint8_t* frame, std::size_t len, std::size_t off,
               std::size_t& ip_off, Direction& dir, bool& opaque,
               ParsedFrame& out) noexcept {
  if (off + kDot11FrameControlLen > len) {
    out.err = "802.11 çerçevesi frame control için çok kısa";
    return false;
  }

  const std::uint8_t fc0 = frame[off];
  const std::uint8_t type = static_cast<std::uint8_t>((fc0 >> 2) & 0x03u);
  if (type == 0) {
    out.err = "802.11 yönetim çerçevesi (veri değil)";
    return false;
  }
  if (type == 1) {
    out.err = "802.11 kontrol çerçevesi (veri değil)";
    return false;
  }
  if (type != kDot11TypeData) {
    out.err = "802.11 genişletme çerçevesi (veri değil)";
    return false;
  }

  const bool to_ds = (fc0 & 0x01u) != 0;
  const bool from_ds = (fc0 & 0x02u) != 0;
  const bool protected_body = (fc0 & 0x40u) != 0;
  const std::uint8_t subtype = static_cast<std::uint8_t>((fc0 >> 4) & 0x0Fu);
  const bool qos = (subtype & kDot11QosSubtypeBit) != 0;

  // Adres alanları sabit 24 bayt; QoS veri çerçevesinde 2 bayt QoS kontrolü,
  // Order biti ile birlikte 4 bayt HT kontrolü daha eklenir.
  std::size_t header_len = kDot11HeaderLen;
  if (qos) header_len += kDot11QosLen;
  if (qos && (fc0 & kDot11OrderBit) != 0) header_len += kDot11HtControlLen;

  // Şifreli gövdede LLC/SNAP görünmez; yalnızca başlık sınırı aranır.
  if (off + header_len > len || (!protected_body && off + header_len + kSnapHeaderLen > len)) {
    out.err = "802.11 çerçevesi LLC/SNAP için çok kısa";
    return false;
  }

  // Yön kuralı: ToDS=1/FromDS=0 giden, ToDS=0/FromDS=1 gelen. WDS (1/1) ve
  // ad-hoc (0/0) çerçevesinde yön başlıktan çıkmaz; kaynak/hedef MAC
  // karşılaştırması yerine belgelenmiş varsayılan Out kullanılır.
  if (!to_ds && from_ds) {
    dir = Direction::In;
  } else {
    dir = Direction::Out;
  }

  const std::size_t snap = off + header_len;
  const std::uint8_t* s = frame + snap;
  // Şifreli gövdede LLC/SNAP olmayabilir: okuma kalan uzunluğa bağlı.
  const bool snap_ok = len - snap >= kSnapHeaderLen && s[0] == 0xAA && s[1] == 0xAA &&
                       s[2] == 0x03 && s[3] == 0x00 && s[4] == 0x00 && s[5] == 0x00;

  if (snap_ok) {
    const std::uint16_t ether_type = readBe16(s + 6);
    if (ether_type == kEtherTypeIPv4 || ether_type == kEtherTypeIPv6) {
      const std::size_t candidate = snap + kSnapHeaderLen;
      if (etherTypeMatchesIp(frame, len, candidate, ether_type)) {
        ip_off = candidate;
        return true;
      }
      if (!protected_body) {
        out.err = "EtherType ile IP sürümü uyuşmuyor";
        return false;
      }
    } else if (!protected_body) {
      out.err = "LLC/SNAP sonrası EtherType IP değil";
      return false;
    }
  } else if (!protected_body) {
    out.err = "802.11 gövdesinde LLC/SNAP başlığı yok";
    return false;
  }

  // Şifreli gövde: LLC/SNAP ve portlar okunamaz. Çözülemeyen içerik hata
  // sayılmaz; gövde ham payload olarak verilir, yön yalnızca DS bitlerinden gelir.
  ip_off = snap;
  opaque = true;
  return true;
}
}  // namespace

bool isTargetPort(std::uint16_t port) noexcept {
  return port == kPortSingle || (port >= kPortLow && port <= kPortHigh);
}

bool parseFrame(const std::uint8_t* frame, std::size_t len, ParsedFrame& out,
                LinkType link) noexcept {
  if (frame == nullptr) return false;

  std::size_t off = 0;
  // 802.11'de DS bitlerinden çıkan yön; WDS/ad-hoc'ta belgelenmiş varsayılan.
  Direction dot11_dir = Direction::Out;
  // Şifreli gövde: IP/TCP başlıkları okunamaz, payload ham verilir.
  bool opaque = false;

  if (link == LinkType::Ethernet) {
    if (len < kEtherHeaderLen) return false;
    off = kEtherHeaderLen;

    std::uint16_t ether_type = readBe16(frame + 12);
    // VLAN / QinQ etiketlerini sırayla atla.
    for (std::size_t tags = 0; tags < kMaxVlanTags; ++tags) {
      if (ether_type != kEtherTypeVlan && ether_type != kEtherTypeQinQ &&
          ether_type != kEtherTypeVlan9100) {
        break;
      }
      if (off + kVlanTagLen > len) return false;
      ether_type = readBe16(frame + off + 2);
      off += kVlanTagLen;
    }

    if (ether_type != kEtherTypeIPv4 && ether_type != kEtherTypeIPv6) return false;
    if (!etherTypeMatchesIp(frame, len, off, ether_type)) return false;
  } else if (link == LinkType::NullLoop) {
    if (!skipNullFamily(frame, len, off)) return false;
  } else if (link == LinkType::Dot11 || link == LinkType::Dot11Radio) {
    if (link == LinkType::Dot11Radio) {
      // Radiotap başlığı: it_len kadar atlanır; uzunluk çerçeveyi aşamaz.
      if (len < kRadiotapMinLen) {
        out.err = "radiotap başlığı için çerçeve çok kısa";
        return false;
      }
      if (frame[0] != kRadiotapVersion) {
        out.err = "radiotap sürümü desteklenmiyor";
        return false;
      }
      const std::size_t radiotap_len = readLe16(frame + kRadiotapLenOffset);
      if (radiotap_len < kRadiotapMinLen) {
        out.err = "radiotap başlık uzunluğu geçersiz";
        return false;
      }
      if (radiotap_len > len) {
        out.err = "radiotap başlığı çerçeveyi aşıyor";
        return false;
      }
      off = radiotap_len;
    }

    std::size_t ip_off = 0;
    if (!walkDot11(frame, len, off, ip_off, dot11_dir, opaque, out)) return false;
    off = ip_off;
  }

  if (opaque) {
    // Şifreli gövde: portlar okunamaz, yalnızca DS bitlerinden gelen yön vardır.
    out.payload = frame + off;
    out.payload_len = len - off;
    out.dir = dot11_dir;
    return out.payload_len > 0;
  }

  std::size_t tcp_off = 0;
  if (!walkIp(frame, len, off, tcp_off)) return false;

  if (tcp_off + kTCPMinHeaderLen > len) return false;

  const std::uint16_t src_port = readBe16(frame + tcp_off);
  const std::uint16_t dst_port = readBe16(frame + tcp_off + 2);

  const std::size_t data_off = static_cast<std::size_t>(frame[tcp_off + 12] >> 4) * 4;
  if (data_off < kTCPMinHeaderLen) return false;
  if (tcp_off + data_off > len) return false;

  const std::size_t payload_off = tcp_off + data_off;
  const std::size_t payload_len = len - payload_off;
  if (payload_len == 0) return false;

  // Yön: hedef port dinlenen aralıkta ise giden, kaynak port ise gelen.
  if (isTargetPort(dst_port)) {
    out.dir = Direction::Out;
  } else if (isTargetPort(src_port)) {
    out.dir = Direction::In;
  } else {
    return false;
  }

  // 802.11'de DS bitleri port tahminini ezer; WDS (1/1) ve ad-hoc (0/0)
  // çerçevesinde belgelenmiş varsayılan Out kullanılır.
  if (link == LinkType::Dot11 || link == LinkType::Dot11Radio) out.dir = dot11_dir;

  out.payload = frame + payload_off;
  out.payload_len = payload_len;
  return true;
}

}  // namespace ko::net
