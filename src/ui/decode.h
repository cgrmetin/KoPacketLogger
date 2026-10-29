#pragma once

#include <cstdint>
#include <vector>

#include "core/decoder.h"
#include "core/frame.h"
#include "core/types.h"

namespace ko::ui {

// TCP akisini cercevelere boler ve her cerceveyi ko::Decoder ile cozumer.
// ko::Decoder tek cerceve bekledigi icin bolme burada yapilir.
// Yalnizca UI thread'inden kullanilir; ic durumu kilit gerektirmez.
class PacketPipeline {
public:
  // Ham paketi isler; uretilen cozulmus paketleri `out`a ekler.
  // Bir paket birden fazla cerceve icerirse her biri ayri satir olur.
  void process(const RawPacket& raw, std::vector<DecodedPacket>& out);

  // Baglanti yeniden kurulduğunda akis tamponunu ve anahtar durumunu atar.
  void reset();

  bool hasClientKey() const { return decoder_.hasClientKey(); }

private:
  FrameParser parser_;
  Decoder decoder_;
};

} // namespace ko::ui
