#pragma once

#include <cstdint>
#include <fstream>
#include <string>

#include "core/types.h"

namespace ko::ui {

// Paketleri okunabilir bir .log dosyasina yazar. Kayit kapaliyken cagrilar yok sayilir.
class LogWriter {
public:
  LogWriter() = default;
  ~LogWriter();

  LogWriter(const LogWriter&) = delete;
  LogWriter& operator=(const LogWriter&) = delete;

  // Dosyayi acar. Hata halinde false doner ve `error` doldurulur.
  bool open(const std::string& path, std::string& error);
  void close();
  bool isOpen() const { return file_.is_open(); }

  // Cozulmus paketi yazar. Yazilan byte sayisini dondurur.
  std::size_t write(const DecodedPacket& packet);

  const std::string& path() const { return path_; }
  std::uint64_t writtenCount() const { return written_; }

private:
  std::ofstream file_;
  std::string path_;
  std::uint64_t written_ = 0;
};

} // namespace ko::ui
