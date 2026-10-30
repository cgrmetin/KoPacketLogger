#pragma once

#include <map>
#include <string>

namespace ko::ui {

// Arayuz tercihleri icin basit "anahtar=deger" deposu.
// ImGui'nin kendi ini dosyasina dokunmaz; ondan turetilen ayri bir dosya kullanilir.
class SettingsStore {
public:
  // IniFilename'den turetilen ayar dosyasi yolu. IniFilename'in dizini varsa
  // oraya "ui.ini" konur; aksi halde %LOCALAPPDATA%\KoPacketLogger\ui.ini.
  static std::string derivePath(const char* iniFilename);

  // Dosyayi okur. Dosya yoksa sessizce gecer; bozuk satirlar atlanir.
  void load(const std::string& path);

  // Dosyayi yazar. Dizin yoksa olusturulur; hata `err` alanina yazilir.
  bool save(const std::string& path, std::string& err) const;

  bool getBool(const std::string& key, bool fallback) const;
  void setBool(const std::string& key, bool value);

private:
  std::map<std::string, std::string> values_;
};

} // namespace ko::ui
