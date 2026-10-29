#include "ui/packet_buffer.h"

#include <algorithm>

namespace ko::ui {

PacketBuffer::PacketBuffer(std::size_t capacity) : capacity_(std::max<std::size_t>(capacity, 1'000)) {}

void PacketBuffer::push(RawPacket&& packet) {
  captured_.fetch_add(1, std::memory_order_relaxed);
  if (paused_.load(std::memory_order_relaxed)) {
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  pending_.push_back(std::move(packet));
  while (pending_.size() > capacity_) {
    pending_.pop_front();
    dropped_.fetch_add(1, std::memory_order_relaxed);
  }
}

std::size_t PacketBuffer::drain(std::vector<RawPacket>& out) {
  std::lock_guard<std::mutex> lock(mutex_);
  const std::size_t take = std::min(pending_.size(), kMaxDrainPerFrame);
  out.reserve(out.size() + take);
  for (std::size_t i = 0; i < take; ++i) {
    out.push_back(std::move(pending_.front()));
    pending_.pop_front();
  }
  return take;
}

void PacketBuffer::setPaused(bool paused) { paused_.store(paused, std::memory_order_relaxed); }

void PacketBuffer::setCapacity(std::size_t capacity) {
  std::lock_guard<std::mutex> lock(mutex_);
  capacity_ = std::max<std::size_t>(capacity, 1'000);
  while (pending_.size() > capacity_) {
    pending_.pop_front();
    dropped_.fetch_add(1, std::memory_order_relaxed);
  }
}

std::size_t PacketBuffer::capacity() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return capacity_;
}

std::size_t PacketBuffer::pending() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return pending_.size();
}

void PacketBuffer::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  pending_.clear();
}

void PacketBuffer::resetCounters() {
  captured_.store(0, std::memory_order_relaxed);
  dropped_.store(0, std::memory_order_relaxed);
}

} // namespace ko::ui
