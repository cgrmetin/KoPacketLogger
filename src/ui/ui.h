#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "app.h"
#include "capture/capture.h"
#include "core/types.h"
#include "ui/decode.h"
#include "ui/filters.h"
#include "ui/log_writer.h"
#include "ui/packet_buffer.h"
#include "ui/settings.h"

namespace ko::ui {

// Tek bir liste satiri. `seq` monoton artar; secim ve filtre listesi buna gore tutulur.
struct Row {
  std::uint64_t seq = 0;
  DecodedPacket packet;
};

// Tum arayuz durumu ve cizimi. Yalnizca UI thread'inden kullanilir.
class Ui {
public:
  explicit Ui(AppState& state);
  ~Ui();

  Ui(const Ui&) = delete;
  Ui& operator=(const Ui&) = delete;

  // Ilk yerlesimi ve cihaz listesini hazirlar. ImGui baglami kurulduktan sonra cagrilir.
  void initialize();

  // Bir kare cizer ve bekleyen paketleri isler.
  void frame();

private:
  // --- paneller ---
  void drawDockSpace();
  void drawMenuBarAndToolbar();
  void drawFilterBar();
  void drawPacketList();
  void drawDetailPanel();
  void drawHexDump(const std::vector<std::uint8_t>& data, const char* caption);
  void drawFieldTable(const DecodedPacket& packet);
  void drawWarningsPanel();
  void drawWikiPanel();
  void drawStatusBar();

  // --- veri akisi ---
  void pumpCapture();
  void appendDecoded(DecodedPacket&& packet, std::uint64_t seq, bool accepted);
  void rebuildFiltered();
  void evictOverflow();
  bool filtersArePassThrough() const;

  // --- eylemler ---
  void refreshDevices();
  void startCapture();
  void stopCapture();
  void togglePause();
  void clearPackets();
  void toggleLogging();
  void selectRow(std::uint64_t seq);
  const Row* selectedRow() const;
  const Row* rowForSeq(std::uint64_t seq) const;

  void setStatus(std::string text);
  void setError(std::string text);

  // --- kalicilik ---
  void loadPreferences();
  void savePreferences();

  // --- durum ---
  AppState& state_;
  Capture capture_;
  PacketBuffer buffer_;
  PacketPipeline pipeline_;
  LogWriter log_;

  std::deque<Row> rows_;
  std::vector<std::uint64_t> filtered_;
  std::uint64_t nextSeq_ = 1;
  std::uint64_t selectedSeq_ = 0;

  FilterState filters_;
  PreparedFilter prepared_;
  bool filtersDirty_ = true;

  std::vector<RawPacket> drainScratch_;
  std::vector<DecodedPacket> decodeScratch_;

  int selectedDevice_ = -1;
  std::size_t capacity_ = PacketBuffer::kDefaultCapacity;

  bool npcapPresent_ = false;
  bool layoutBuilt_ = false;
  bool showWarnings_ = true;
  bool showWiki_ = true;
  bool filterBarOpen_ = true;
  bool autoScroll_ = true;
  bool followTail_ = true;
  float lastScrollY_ = 0.0f;
  bool scrollInitialized_ = false;

  // Arayuz tercihleri; kapanista bir kez yazilir.
  SettingsStore settings_;
  std::string settingsPath_;
  std::string wikiText_;
  char wikiFilter_[128] = {};
  bool wikiDirty_ = true;

  bool preferencesLoaded_ = false;

  double rate_ = 0.0;
  std::uint64_t rateCount_ = 0;
  double rateWindowStart_ = 0.0;
  double lastFrameTime_ = 0.0;
  float frameMs_ = 0.0f;

  std::string logError_;
  std::string logDirectory_;
};

} // namespace ko::ui
