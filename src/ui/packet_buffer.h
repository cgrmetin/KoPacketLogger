#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "core/types.h"

namespace ko::ui {

// Yakalama thread'i ile UI thread'i arasindaki tek temas noktasi.
// Sink buraya yazar (kisa kilit), UI her karede sinirli sayida paket ceker.
// Bekleyen kuyruk siniirlidir: UI yetisemezse en eski bekleyen paket dusurulur.
class PacketBuffer {
public:
  static constexpr std::size_t kDefaultCapacity = 200'000;
  static constexpr std::size_t kMaxDrainPerFrame = 5'000;

  explicit PacketBuffer(std::size_t capacity = kDefaultCapacity);

  // Yakalama thread'inden cagrilir. Duraklatilmisken paket yutulur.
  void push(RawPacket&& packet);

  // UI thread'inden cagrilir. En fazla kMaxDrainPerFrame paket tasir.
  // Donen deger: bu karede tasinan paket sayisi.
  std::size_t drain(std::vector<RawPacket>& out);

  void setPaused(bool paused);
  bool paused() const { return paused_.load(std::memory_order_relaxed); }

  void setCapacity(std::size_t capacity);
  std::size_t capacity() const;

  // Bekleyen (henuz UI'a tasinmamis) paket sayisi.
  std::size_t pending() const;

  void clear();

  std::uint64_t capturedTotal() const { return captured_.load(std::memory_order_relaxed); }
  std::uint64_t droppedTotal() const { return dropped_.load(std::memory_order_relaxed); }
  void resetCounters();

private:
  mutable std::mutex mutex_;
  std::deque<RawPacket> pending_;
  std::size_t capacity_;
  std::atomic<bool> paused_{false};
  std::atomic<std::uint64_t> captured_{0};
  std::atomic<std::uint64_t> dropped_{0};
};

} // namespace ko::ui
