#pragma once
#include <cstdint>
#include <string>

#include "core/aes.h"
#include "core/types.h"

namespace ko {

// Çözücü (IDA: pkt_decrypt_check @ 0x8E3250, aes_crypt_cbc @ 0x707C60).
//
// Gövde ÜÇ modda yorumlanır ve sıra önemlidir:
//  1. Şifresiz mod: anahtar yoksa veya şifreleme kapalıyken gövde düzdür:
//     [opcode][alanlar]. Handshake bu modda gelir.
//  2. Şifreli mod: gövde[0] anahtar seçicisidir (1 oturum, 2 sabit anahtar).
//     GİDEN yönde sıra baytı vardır: [seçici][sıra][opcode][alanlar].
//     GELEN yönde sıra baytı YOKTUR: [seçici][opcode][alanlar].
//
// Seçici kararı boyut kuralıyla birlikte verilir, çünkü düz modda opcode 0x01
// veya 0x02 olabilir: gövde[0] ∈ {1,2} VE (len & 0xF) == 1 VE len >= 17 ise
// şifreli sayılır; aksi halde düz mod.
//
// Çözülmüş düz metin FC 1E ile başlıyorsa ilk 5 bayt atılır. Sıra önce Out
// yönünde ayıklanır, sonra FC 1E kırpması yapılır.
//
// Tek iş parçacığından kullanılır; iç eşitleme yok.
class Decoder {
 public:
  Decoder() = default;

  // Gövdeyi çözer. Hata durumunda `ok=false`, `error` dolu döner; sessiz yutma yok.
  DecodedPacket decode(const RawPacket& raw);

  // Kolaylık: ham gövde baytlarından RawPacket kurup çözer.
  DecodedPacket decode(Direction dir, std::int64_t tsUnixUs,
                       const std::vector<std::uint8_t>& body);

  // Handshake gövdesinden oturum anahtarını alır (bkz. dump-analiz §4.3).
  // Başarısızsa `error` doldurulur ve anahtar durumu değişmez.
  bool captureSessionKey(const std::vector<std::uint8_t>& body, std::string& error);

  // Bağlantı yeniden kurulduğunda çağrılır: anahtar, sayaç ve şifreleme durumu sıfırlanır.
  void reset() noexcept;

  // Şifreleme açık mı? Handshake ile gelen bayrak (byte_1129B34).
  void setEncryptionEnabled(bool enabled) noexcept { encryptionEnabled_ = enabled; }
  bool encryptionEnabled() const noexcept { return encryptionEnabled_; }

  bool hasSessionKey() const noexcept { return sessionKey_.valid(); }
  // Eski ad: arayüz bu isimle soruyor.
  bool hasClientKey() const noexcept { return hasSessionKey(); }

  // Giden sıra numarası sayacı: 1..250, 0xFA üstü 1'e sarar (0x8e347a).
  // Anahtar yoksa veya şifreleme kapalıysa 0 döner.
  std::uint8_t nextSeq() noexcept;

 private:
  // Gövde şifreli mi? Boyut kuralı + seçici kontrolü.
  static bool looksEncrypted(const std::vector<std::uint8_t>& body) noexcept;

  // Seçiciye göre anahtarı seçer; geçersizse nullptr.
  const AesKey* keyFor(std::uint8_t selector) const noexcept;

  AesKey sessionKey_{};
  bool encryptionEnabled_ = false;
  std::uint8_t seqCounter_ = 0;
};

}  // namespace ko
