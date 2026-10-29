#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "capture/capture.h"
#include "core/types.h"

namespace ko {

// Uygulama genel durumu. UI thread'i yazar, capture thread'i okur.
struct AppState {
  std::atomic<bool> capturing{false};
  std::atomic<bool> quit{false};
  std::atomic<std::uint64_t> dropped{0};

  std::mutex devicesMutex;
  std::vector<DeviceInfo> devices;
  int selectedDevice = -1;

  std::string status;
  std::string error;
};

} // namespace ko
