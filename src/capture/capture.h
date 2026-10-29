#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "core/types.h"
namespace ko {
struct DeviceInfo { std::string name; std::string description; };
class Capture {
public:
  Capture(); ~Capture();
  Capture(const Capture&) = delete; Capture& operator=(const Capture&) = delete;
  static std::vector<DeviceInfo> listDevices();
  bool start(const std::string& device, std::string& err);
  void stop();
  bool running() const;
  void setSink(std::function<void(RawPacket&&)> sink);
  std::uint64_t dropped() const;
private:
  struct Impl; Impl* impl_;
};
}
