#include "ui/decode.h"

namespace ko::ui {

void PacketPipeline::reset() {
  parser_.resetAll();
  decoder_.reset();
}

void PacketPipeline::process(const RawPacket& raw, std::vector<DecodedPacket>& out) {
  std::vector<Frame> frames;
  parser_.feed(raw.dir, raw.data.data(), raw.data.size(), frames);

  if (frames.empty()) {
    // Yalnizca akis devam ediyor demektir; her segment icin satir uretmek
    // listeyi gereksiz sisirir. Yalnizca gercek bir hata varsa gorunur kayit yapilir.
    return;
  }

  for (Frame& frame : frames) {
    RawPacket frameRaw;
    frameRaw.ts_unix_us = raw.ts_unix_us;
    frameRaw.dir = raw.dir;
    frameRaw.data = std::move(frame.raw);
    out.push_back(decoder_.decode(frameRaw));
  }
}

} // namespace ko::ui
