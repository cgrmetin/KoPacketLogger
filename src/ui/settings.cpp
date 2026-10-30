#include "ui/settings.h"

#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <system_error>
#include <vector>

namespace ko::ui {
namespace {

constexpr const char* kDefaultDirectory = "KoPacketLogger";
constexpr const char* kFileName = "ui.ini";
constexpr const char* kTrueTokens[] = {"1", "true", "on", "evet", "yes"};

std::string trim(const std::string& text) {
  const std::size_t first = text.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  const std::size_t last = text.find_last_not_of(" \t\r\n");
  return text.substr(first, last - first + 1);
}

std::string localAppDataDirectory() {
  // %LOCALAPPDATA% yoksa gecici dizine dusulur; boylece ayar yolu her zaman gecerli olur.
  std::vector<wchar_t> buffer(MAX_PATH);
  for (;;) {
    const DWORD written =
        ::GetEnvironmentVariableW(L"LOCALAPPDATA", buffer.data(), static_cast<DWORD>(buffer.size()));
    if (written == 0) break;
    if (written < buffer.size()) {
      const std::filesystem::path base(std::wstring(buffer.data(), written));
      return (base / kDefaultDirectory).string();
    }
    buffer.resize(static_cast<std::size_t>(written) + 1);
  }

  std::error_code ec;
  const std::filesystem::path fallback = std::filesystem::temp_directory_path(ec);
  if (ec) return kDefaultDirectory;
  return (fallback / kDefaultDirectory).string();
}

} // namespace

std::string SettingsStore::derivePath(const char* iniFilename) {
  // IniFilename mutlaksa ve bir dizin iceriyorsa o dizin kullanilir; dosya adi her zaman ui.ini.
  // Dizin yoksa (yalnizca dosya adi) %LOCALAPPDATA%\KoPacketLogger altina yazilir.
  if (iniFilename != nullptr && iniFilename[0] != '\0') {
    const std::filesystem::path ini(iniFilename);
    const std::filesystem::path directory = ini.parent_path();
    if (!directory.empty()) return (directory / kFileName).string();
  }
  return (std::filesystem::path(localAppDataDirectory()) / kFileName).string();
}

void SettingsStore::load(const std::string& path) {
  values_.clear();

  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) return;

  std::FILE* file = nullptr;
  if (fopen_s(&file, path.c_str(), "rb") != 0 || file == nullptr) return;

  std::string text;
  char chunk[512];
  while (const std::size_t read = std::fread(chunk, 1, sizeof(chunk), file)) text.append(chunk, read);
  std::fclose(file);

  std::size_t pos = 0;
  while (pos <= text.size()) {
    const std::size_t end = text.find('\n', pos);
    const std::string line = trim(text.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
    if (end == std::string::npos) {
      if (!line.empty()) {
        const std::size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0) values_[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
      }
      break;
    }

    // Bos satirlar ve yorumlar sessizce atlanir.
    if (!line.empty() && line[0] != '#' && line[0] != ';') {
      const std::size_t eq = line.find('=');
      if (eq != std::string::npos && eq > 0) values_[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }
    pos = end + 1;
  }
}

bool SettingsStore::save(const std::string& path, std::string& err) const {
  const std::filesystem::path target(path);
  std::error_code ec;
  if (target.has_parent_path()) std::filesystem::create_directories(target.parent_path(), ec);
  if (ec) {
    err = "Ayar dizini olusturulamadi: " + ec.message();
    return false;
  }

  std::FILE* file = nullptr;
  if (fopen_s(&file, path.c_str(), "wb") != 0 || file == nullptr) {
    err = "Ayar dosyasi yazilamadi: " + path;
    return false;
  }

  std::fputs("# KoPacketLogger arayuz ayarlari\n", file);
  for (const auto& [key, value] : values_) {
    std::fprintf(file, "%s=%s\n", key.c_str(), value.c_str());
  }
  const bool ok = std::fclose(file) == 0;
  if (!ok) err = "Ayar dosyasi kapatilamadi: " + path;
  return ok;
}

bool SettingsStore::getBool(const std::string& key, bool fallback) const {
  const auto it = values_.find(key);
  if (it == values_.end()) return fallback;
  if (it->second == "0" || it->second == "false" || it->second == "off" || it->second == "hayir" ||
      it->second == "no") {
    return false;
  }
  for (const char* token : kTrueTokens) {
    if (it->second == token) return true;
  }
  return fallback;
}

void SettingsStore::setBool(const std::string& key, bool value) { values_[key] = value ? "1" : "0"; }

} // namespace ko::ui
