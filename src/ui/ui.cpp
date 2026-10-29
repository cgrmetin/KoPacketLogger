#include "ui/ui.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <string>
#include <system_error>

#include "imgui.h"
#include "imgui_internal.h"

#include "core/opcodes.h"
#include "ui/theme.h"

namespace ko::ui {
namespace {

// Toolbar ve durum cubugu sabit yukseklikte; dockspace araligi bunlara gore hesaplanir.
constexpr float kToolbarHeight = 70.0f;
constexpr float kStatusBarHeight = 26.0f;
constexpr int kHexBytesPerRow = 16;

constexpr ImGuiTableFlags kDetailTableFlags =
    ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_BordersOuterH |
    ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_BordersOuterV | ImGuiTableFlags_RowBg;

bool wpcapPresent() {
  HMODULE module = ::LoadLibraryW(L"wpcap.dll");
  if (module == nullptr) return false;
  ::FreeLibrary(module);
  return true;
}

std::string clockString(std::int64_t tsUnixUs) {
  if (tsUnixUs <= 0) return "--:--:--.---";
  const std::time_t seconds = static_cast<std::time_t>(tsUnixUs / 1'000'000);
  const int millis = static_cast<int>((tsUnixUs % 1'000'000) / 1'000);
  std::tm local{};
  localtime_s(&local, &seconds);
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d.%03d", local.tm_hour, local.tm_min, local.tm_sec, millis);
  return buffer;
}

const char* directionLabel(Direction dir) { return dir == Direction::In ? "GELEN" : "GIDEN"; }

const char* cryptionLabel(Cryption cryption) {
  switch (cryption) {
    case Cryption::Client: return "Client (istemci -> sunucu)";
    case Cryption::Server: return "Server (sunucu -> istemci)";
    case Cryption::Unknown: return "Bilinmiyor";
  }
  return "Bilinmiyor";
}

std::string asciiPreview(const std::vector<std::uint8_t>& data, std::size_t maxChars) {
  std::string out;
  const std::size_t limit = std::min<std::size_t>(data.size(), maxChars);
  out.reserve(limit);
  for (std::size_t i = 0; i < limit; ++i) {
    const unsigned char c = data[i];
    out.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '.');
  }
  if (data.size() > limit) out += "...";
  return out;
}

std::string bytesToLowerHex(const std::uint8_t* data, std::size_t count) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(count * 2);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0F]);
  }
  return out;
}

std::uint64_t readLE(const std::uint8_t* data, std::size_t count) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < count; ++i) value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
  return value;
}

std::uint64_t readBE(const std::uint8_t* data, std::size_t count) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < count; ++i) value = (value << 8) | data[i];
  return value;
}

// Kisa bir bayt serisinden okunabilir onizleme.
std::string summarize(const DecodedPacket& packet) {
  const std::vector<std::uint8_t>& data = packet.plain.empty() ? packet.raw.data : packet.plain;
  if (data.empty()) return "(bos)";
  std::string out = bytesToLowerHex(data.data(), std::min<std::size_t>(data.size(), 8));
  if (data.size() >= 2) {
    char tail[48];
    std::snprintf(tail, sizeof(tail), "  [%u..%u]", static_cast<unsigned>(readLE(data.data(), 2)),
                  static_cast<unsigned>(readBE(data.data(), 2)));
    out += tail;
  }
  if (data.size() > 8) out += " ...";
  return out;
}

} // namespace

Ui::Ui(AppState& state) : state_(state), buffer_(PacketBuffer::kDefaultCapacity) {
  capture_.setSink([this](RawPacket&& packet) { buffer_.push(std::move(packet)); });
  npcapPresent_ = wpcapPresent();
  logDirectory_ = "logs";
}

Ui::~Ui() { stopCapture(); }

void Ui::initialize() {
  refreshDevices();
  if (!npcapPresent_) {
    setError("Npcap surucusu kurulu degil (wpcap.dll yuklenemiyor). Npcap kurulduktan sonra uygulamayi yeniden baslatin.");
  } else if (selectedDevice_ < 0) {
    setError("Kullanilabilir ag adaptoru bulunamadi. Ag baglantisini kontrol edip Yenile'ye basin.");
  } else {
    setStatus("Hazir. Yakalamak icin Baslat'a basin.");
  }
}

// ---------------------------------------------------------------------------
// Veri akisi
// ---------------------------------------------------------------------------

bool Ui::filtersArePassThrough() const {
  return prepared_.showIn && prepared_.showOut && !prepared_.errorsOnly && !prepared_.opcodeRange &&
         !prepared_.nameContains && !prepared_.sizeRange && !prepared_.text;
}

void Ui::pumpCapture() {
  const double now = ImGui::GetTime();
  const double elapsed = now - rateWindowStart_;
  if (elapsed >= 0.5) {
    rate_ = static_cast<double>(rateCount_) / elapsed;
    rateCount_ = 0;
    rateWindowStart_ = now;
  }

  drainScratch_.clear();
  const std::size_t drained = buffer_.drain(drainScratch_);
  rateCount_ += static_cast<std::uint64_t>(drained);
  state_.dropped.store(buffer_.droppedTotal(), std::memory_order_relaxed);
  if (drained == 0) return;

  decodeScratch_.clear();
  for (const RawPacket& raw : drainScratch_) pipeline_.process(raw, decodeScratch_);
  if (decodeScratch_.empty()) return;

  const bool passThrough = filtersArePassThrough();
  for (DecodedPacket& decoded : decodeScratch_) {
    const std::uint64_t seq = nextSeq_++;
    appendDecoded(std::move(decoded), seq, passThrough || prepared_.matches(decoded));
  }
  evictOverflow();
}

void Ui::appendDecoded(DecodedPacket&& packet, std::uint64_t seq, bool accepted) {
  Row row;
  row.seq = seq;
  row.packet = std::move(packet);
  rows_.push_back(std::move(row));
  if (accepted) filtered_.push_back(seq);
}

void Ui::evictOverflow() {
  while (rows_.size() > capacity_) {
    const std::uint64_t evicted = rows_.front().seq;
    rows_.pop_front();
    if (!filtered_.empty() && filtered_.front() == evicted) {
      filtered_.erase(filtered_.begin());
    }
    if (selectedSeq_ == evicted) selectedSeq_ = 0;
  }
}

void Ui::rebuildFiltered() {
  filtered_.clear();
  const bool passThrough = filtersArePassThrough();
  for (const Row& row : rows_) {
    if (passThrough || prepared_.matches(row.packet)) filtered_.push_back(row.seq);
  }
  if (selectedSeq_ != 0 && !std::binary_search(filtered_.begin(), filtered_.end(), selectedSeq_)) {
    selectedSeq_ = 0;
  }
  filtersDirty_ = false;
}

const Row* Ui::rowForSeq(std::uint64_t seq) const {
  if (rows_.empty() || seq < rows_.front().seq) return nullptr;
  const std::uint64_t index = seq - rows_.front().seq;
  if (index >= rows_.size()) return nullptr;
  const Row& row = rows_[static_cast<std::size_t>(index)];
  return row.seq == seq ? &row : nullptr;
}

const Row* Ui::selectedRow() const { return rowForSeq(selectedSeq_); }

void Ui::selectRow(std::uint64_t seq) { selectedSeq_ = seq; }

// ---------------------------------------------------------------------------
// Eylemler
// ---------------------------------------------------------------------------

void Ui::refreshDevices() {
  std::vector<DeviceInfo> devices = Capture::listDevices();
  npcapPresent_ = wpcapPresent();

  {
    std::lock_guard<std::mutex> lock(state_.devicesMutex);
    state_.devices = devices;
  }

  if (devices.empty()) {
    selectedDevice_ = -1;
  } else if (selectedDevice_ < 0 || selectedDevice_ >= static_cast<int>(devices.size())) {
    selectedDevice_ = 0;
  }
  state_.selectedDevice = selectedDevice_;
}

void Ui::startCapture() {
  if (capture_.running() || selectedDevice_ < 0) {
    if (selectedDevice_ < 0) setError("Once bir ag adaptoru secin.");
    return;
  }

  std::string deviceName;
  {
    std::lock_guard<std::mutex> lock(state_.devicesMutex);
    deviceName = state_.devices[static_cast<std::size_t>(selectedDevice_)].name;
  }

  pipeline_.reset();

  std::string err;
  if (!capture_.start(deviceName, err)) {
    setError(err);
    state_.capturing.store(false, std::memory_order_relaxed);
    return;
  }

  buffer_.setPaused(false);
  state_.capturing.store(true, std::memory_order_relaxed);
  state_.error.clear();
  setStatus("Yakalama suruyor.");
}

void Ui::stopCapture() {
  if (capture_.running()) {
    capture_.stop();
    setStatus("Yakalama durduruldu.");
  }
  state_.capturing.store(false, std::memory_order_relaxed);
}

void Ui::togglePause() {
  const bool paused = !buffer_.paused();
  buffer_.setPaused(paused);
  setStatus(paused ? "Duraklatildi; gelen paketler birakiliyor." : "Yakalama suruyor.");
}

void Ui::clearPackets() {
  rows_.clear();
  filtered_.clear();
  selectedSeq_ = 0;
  nextSeq_ = 1;
  pipeline_.reset();
  filtersDirty_ = true;
  setStatus("Paket listesi temizlendi.");
}

void Ui::toggleLogging() {
  if (log_.isOpen()) {
    const std::string path = log_.path();
    log_.close();
    logError_.clear();
    setStatus("Kayit kapatildi: " + path);
    return;
  }

  std::error_code ec;
  std::filesystem::create_directories(logDirectory_, ec);

  std::time_t now = std::time(nullptr);
  std::tm local{};
  localtime_s(&local, &now);
  char name[64];
  std::snprintf(name, sizeof(name), "ko-%04d%02d%02d-%02d%02d%02d.log", local.tm_year + 1900, local.tm_mon + 1,
                local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
  const std::string path = logDirectory_ + "/" + name;

  std::string err;
  if (!log_.open(path, err)) {
    logError_ = err;
    setError(err);
    return;
  }
  logError_.clear();
  setStatus("Kayit acildi: " + path);
}

void Ui::setStatus(std::string text) { state_.status = std::move(text); }

void Ui::setError(std::string text) { state_.error = std::move(text); }

// ---------------------------------------------------------------------------
// Kare
// ---------------------------------------------------------------------------

void Ui::frame() {
  pumpCapture();

  if (filtersDirty_) {
    prepared_ = prepare(filters_);
    rebuildFiltered();
  }

  const double now = ImGui::GetTime();
  if (lastFrameTime_ > 0.0) frameMs_ = static_cast<float>((now - lastFrameTime_) * 1000.0);
  lastFrameTime_ = now;

  drawDockSpace();
  drawMenuBarAndToolbar();
  drawPacketList();
  drawDetailPanel();
  drawWarningsPanel();
  drawStatusBar();
}

void Ui::drawDockSpace() {
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + kToolbarHeight));
  ImGui::SetNextWindowSize(
      ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - kToolbarHeight - kStatusBarHeight));

  constexpr ImGuiWindowFlags kHostFlags =
      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground;

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::Begin("##dockhost", nullptr, kHostFlags);
  ImGui::PopStyleVar();

  const ImGuiID dockspaceId = ImGui::GetID("KoDockspace");
  ImGui::DockSpace(dockspaceId, ImGui::GetContentRegionAvail(), ImGuiDockNodeFlags_None);

  if (!layoutBuilt_) {
    layoutBuilt_ = true;
    const ImVec2 size = ImGui::GetContentRegionAvail();
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, size);

    ImGuiID main = dockspaceId;
    ImGuiID right = 0;
    ImGui::DockBuilderSplitNode(main, ImGuiDir_Right, 0.38f, &right, &main);
    ImGuiID rightBottom = 0;
    ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.32f, &rightBottom, &right);

    ImGui::DockBuilderDockWindow("Paket Listesi", main);
    ImGui::DockBuilderDockWindow("Paket Detayi", rightBottom);
    ImGui::DockBuilderDockWindow("Uyarilar", right);
    ImGui::DockBuilderFinish(dockspaceId);
  }

  ImGui::End();
}

void Ui::drawMenuBarAndToolbar() {
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, kToolbarHeight));
  constexpr ImGuiWindowFlags kFlags =
      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar;

  ImGui::Begin("##toolbar", nullptr, kFlags);

  if (ImGui::BeginMenuBar()) {
    if (ImGui::BeginMenu("Dosya")) {
      if (ImGui::MenuItem(log_.isOpen() ? "Kaydi Kapat" : "Kaydi Ac")) toggleLogging();
      ImGui::Separator();
      if (ImGui::MenuItem("Cikis")) state_.quit.store(true, std::memory_order_relaxed);
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Yakalama")) {
      if (ImGui::MenuItem("Baslat", nullptr, false, !capture_.running() && selectedDevice_ >= 0)) startCapture();
      if (ImGui::MenuItem("Durdur", nullptr, false, capture_.running())) stopCapture();
      if (ImGui::MenuItem(buffer_.paused() ? "Devam Et" : "Duraklat", nullptr, false, capture_.running())) {
        togglePause();
      }
      ImGui::Separator();
      if (ImGui::MenuItem("Temizle")) clearPackets();
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Gorunum")) {
      if (ImGui::MenuItem("Filtre Cubugu", nullptr, filterBarOpen_)) filterBarOpen_ = !filterBarOpen_;
      if (ImGui::MenuItem("Uyari Paneli", nullptr, showWarnings_)) showWarnings_ = !showWarnings_;
      if (ImGui::MenuItem("Otomatik Kaydir", nullptr, autoScroll_)) autoScroll_ = !autoScroll_;
      ImGui::EndMenu();
    }
    ImGui::EndMenuBar();
  }

  // --- adaptor ---
  ImGui::AlignTextToFramePadding();
  ImGui::TextUnformatted("Adaptor:");
  ImGui::SameLine();

  std::vector<DeviceInfo> devices;
  {
    std::lock_guard<std::mutex> lock(state_.devicesMutex);
    devices = state_.devices;
  }

  const char* preview = "(adaptor yok)";
  if (selectedDevice_ >= 0 && selectedDevice_ < static_cast<int>(devices.size())) {
    preview = devices[static_cast<std::size_t>(selectedDevice_)].description.c_str();
  }

  ImGui::SetNextItemWidth(340.0f);
  if (ImGui::BeginCombo("##device", preview)) {
    for (int i = 0; i < static_cast<int>(devices.size()); ++i) {
      const bool selected = i == selectedDevice_;
      if (ImGui::Selectable(devices[static_cast<std::size_t>(i)].description.c_str(), selected)) {
        selectedDevice_ = i;
        state_.selectedDevice = i;
      }
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  ImGui::SameLine();
  if (ImGui::Button("Yenile")) {
    refreshDevices();
    setStatus("Adaptor listesi yenilendi.");
  }

  ImGui::SameLine(0.0f, 16.0f);

  // --- kontrol dugmeleri ---
  if (capture_.running()) {
    if (ImGui::Button("Durdur", ImVec2(88.0f, 0.0f))) stopCapture();
    ImGui::SameLine();
    if (ImGui::Button(buffer_.paused() ? "Devam" : "Duraklat", ImVec2(88.0f, 0.0f))) togglePause();
  } else {
    ImGui::BeginDisabled(selectedDevice_ < 0);
    if (ImGui::Button("Baslat", ImVec2(88.0f, 0.0f))) startCapture();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled();
    ImGui::Button("Duraklat", ImVec2(88.0f, 0.0f));
    ImGui::EndDisabled();
  }

  ImGui::SameLine();
  if (ImGui::Button("Temizle", ImVec2(78.0f, 0.0f))) clearPackets();
  ImGui::SameLine();
  if (ImGui::Button(log_.isOpen() ? "Kayit: Acik" : "Kayit: Kapali", ImVec2(118.0f, 0.0f))) toggleLogging();
  if (log_.isOpen()) {
    ImGui::SameLine();
    ImGui::TextDisabled("%llu satir", static_cast<unsigned long long>(log_.writtenCount()));
  }

  ImGui::SameLine(0.0f, 16.0f);
  ImGui::SetNextItemWidth(260.0f);
  if (ImGui::InputTextWithHint("##search", "Ara: opcode adi, hex veya metin", filters_.text, sizeof(filters_.text))) {
    filtersDirty_ = true;
  }
  ImGui::SameLine();
  if (ImGui::SmallButton("x")) {
    filters_.text[0] = '\0';
    filtersDirty_ = true;
  }

  ImGui::End();
}

void Ui::drawFilterBar() {
  ImGui::AlignTextToFramePadding();
  ImGui::TextUnformatted("Filtreler");
  ImGui::SameLine();
  if (ImGui::SmallButton(filterBarOpen_ ? "Gizle" : "Goster")) filterBarOpen_ = !filterBarOpen_;
  ImGui::SameLine();
  ImGui::TextDisabled("|  Sonuc: %zu / %zu", filtered_.size(), rows_.size());

  if (!filterBarOpen_) return;

  if (ImGui::BeginTable("##filters", 4, ImGuiTableFlags_SizingStretchProp)) {
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    if (ImGui::Checkbox("Gelen", &filters_.showIn)) filtersDirty_ = true;
    ImGui::SameLine();
    if (ImGui::Checkbox("Giden", &filters_.showOut)) filtersDirty_ = true;
    ImGui::SameLine();
    if (ImGui::Checkbox("Sadece hatali", &filters_.errorsOnly)) filtersDirty_ = true;

    ImGui::TableSetColumnIndex(1);
    ImGui::SetNextItemWidth(64.0f);
    if (ImGui::DragInt("##opmin", &filters_.opcodeMin, 1.0f, 0, 255, "0x%02X")) {
      filters_.opcodeRangeEnabled = true;
      filtersDirty_ = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("-");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(64.0f);
    if (ImGui::DragInt("##opmax", &filters_.opcodeMax, 1.0f, 0, 255, "0x%02X")) {
      filters_.opcodeRangeEnabled = true;
      filtersDirty_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("opcode araligi", &filters_.opcodeRangeEnabled)) filtersDirty_ = true;

    ImGui::TableSetColumnIndex(2);
    ImGui::SetNextItemWidth(72.0f);
    if (ImGui::DragInt("##szmin", &filters_.sizeMin, 1.0f, 0, 65535)) {
      filters_.sizeRangeEnabled = true;
      filtersDirty_ = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("-");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(72.0f);
    if (ImGui::DragInt("##szmax", &filters_.sizeMax, 1.0f, 0, 65535)) {
      filters_.sizeRangeEnabled = true;
      filtersDirty_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("boyut araligi", &filters_.sizeRangeEnabled)) filtersDirty_ = true;

    ImGui::TableSetColumnIndex(3);
    ImGui::SetNextItemWidth(200.0f);
    if (ImGui::InputTextWithHint("##namefilter", "Opcode adinda ara", filters_.nameContains,
                                 sizeof(filters_.nameContains))) {
      filtersDirty_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("ad filtresi", &filters_.nameContainsEnabled)) filtersDirty_ = true;

    ImGui::EndTable();
  }
}

void Ui::drawPacketList() {
  ImGui::Begin("Paket Listesi");
  drawFilterBar();

  const float listHeight = ImGui::GetContentRegionAvail().y;
  if (listHeight <= 0.0f) {
    ImGui::End();
    return;
  }

  constexpr ImGuiTableFlags kTableFlags =
      ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
      ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
      ImGuiTableFlags_SizingStretchProp;

  if (ImGui::BeginTable("##packets", 7, kTableFlags, ImVec2(0.0f, listHeight))) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Sira", ImGuiTableColumnFlags_WidthFixed, 56.0f);
    ImGui::TableSetupColumn("Saat (ms)", ImGuiTableColumnFlags_WidthFixed, 96.0f);
    ImGui::TableSetupColumn("Yon", ImGuiTableColumnFlags_WidthFixed, 58.0f);
    ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 62.0f);
    ImGui::TableSetupColumn("Ad", ImGuiTableColumnFlags_WidthStretch, 150.0f);
    ImGui::TableSetupColumn("Boyut", ImGuiTableColumnFlags_WidthFixed, 62.0f);
    ImGui::TableSetupColumn("Ozet", ImGuiTableColumnFlags_WidthStretch, 200.0f);
    ImGui::TableHeadersRow();

    const int total = static_cast<int>(filtered_.size());
    ImGuiListClipper clipper;
    clipper.Begin(total, ImGui::GetTextLineHeightWithSpacing());
    while (clipper.Step()) {
      for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; ++line) {
        const Row* row = rowForSeq(filtered_[static_cast<std::size_t>(line)]);
        if (row == nullptr) continue;

        const DecodedPacket& packet = row->packet;
        const bool incoming = packet.raw.dir == Direction::In;
        const bool known = isKnownOpcode(packet.opcode);
        const bool selected = row->seq == selectedSeq_;

        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(row->seq & 0x7FFFFFFF));

        ImGui::TableSetColumnIndex(0);
        if (ImGui::Selectable("##sel", selected,
                              ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
          selectRow(row->seq);
        }
        ImGui::SameLine();
        ImGui::TextDisabled("%llu", static_cast<unsigned long long>(row->seq));

        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(clockString(packet.raw.ts_unix_us).c_str());

        ImGui::TableSetColumnIndex(2);
        ImGui::PushStyleColor(ImGuiCol_Text, colorForDirection(incoming));
        ImGui::TextUnformatted(directionLabel(packet.raw.dir));
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(3);
        const ImU32 opcodeColor = !packet.ok ? IM_COL32(238, 122, 122, 255)
                                             : (known ? IM_COL32(214, 220, 232, 255) : IM_COL32(238, 176, 112, 255));
        ImGui::PushStyleColor(ImGuiCol_Text, opcodeColor);
        ImGui::Text("0x%02X", packet.opcode);
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(4);
        ImGui::PushStyleColor(ImGuiCol_Text, known ? IM_COL32(206, 212, 224, 255) : IM_COL32(238, 176, 112, 255));
        ImGui::TextUnformatted(packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN");
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(5);
        ImGui::Text("%zu", packet.raw.data.size());

        ImGui::TableSetColumnIndex(6);
        if (!packet.ok) {
          ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(238, 122, 122, 255));
          ImGui::TextUnformatted(packet.error.c_str());
          ImGui::PopStyleColor();
        } else {
          ImGui::TextUnformatted(summarize(packet).c_str());
        }

        ImGui::PopID();
      }
    }

    if (autoScroll_ && total > 0 && ImGui::GetScrollY() < ImGui::GetScrollMaxY()) {
      ImGui::SetScrollY(ImGui::GetScrollMaxY());
    }

    ImGui::EndTable();
  }

  ImGui::End();
}

void Ui::drawDetailPanel() {
  ImGui::Begin("Paket Detayi");

  const Row* row = selectedRow();
  if (row == nullptr) {
    ImGui::TextDisabled("Ayrintilar icin listeden bir paket secin.");
    ImGui::End();
    return;
  }

  const DecodedPacket& packet = row->packet;
  const bool incoming = packet.raw.dir == Direction::In;

  if (ImGui::BeginTable("##summary", 2, kDetailTableFlags)) {
    auto field = [](const char* label) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextDisabled("%s", label);
      ImGui::TableSetColumnIndex(1);
    };

    field("Sira");
    ImGui::Text("%llu", static_cast<unsigned long long>(row->seq));

    field("Saat");
    ImGui::TextUnformatted(clockString(packet.raw.ts_unix_us).c_str());

    field("Yon");
    ImGui::PushStyleColor(ImGuiCol_Text, colorForDirection(incoming));
    ImGui::TextUnformatted(directionLabel(packet.raw.dir));
    ImGui::PopStyleColor();

    field("Kripto");
    ImGui::TextUnformatted(cryptionLabel(packet.cryption));

    field("Opcode");
    ImGui::Text("0x%02X (%u)  %s", packet.opcode, static_cast<unsigned>(packet.opcode),
                packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN");

    field("Uzunluk");
    ImGui::Text("%zu bayt", packet.raw.data.size());

    field("Cozulmus govde");
    ImGui::Text("%zu bayt", packet.plain.size());

    field("Durum");
    if (packet.ok) {
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(150, 214, 160, 255));
      ImGui::TextUnformatted("Cozuldu");
    } else {
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(238, 122, 122, 255));
      ImGui::TextUnformatted(packet.error.c_str());
    }
    ImGui::PopStyleColor();

    ImGui::EndTable();
  }

  ImGui::Separator();

  if (ImGui::BeginTabBar("##detailtabs")) {
    if (ImGui::BeginTabItem("Ham Hex")) {
      drawHexDump(packet.raw.data, "ham cerceve");
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Cozulmus Govde")) {
      if (packet.plain.empty()) {
        ImGui::TextDisabled("Cozulmus govde yok.");
      } else {
        ImGui::TextDisabled("plain[0] = opcode 0x%02X. Asagidaki ofsetler govde alanlaridir.", packet.opcode);
        drawFieldTable(packet.plain);
        ImGui::Separator();
        drawHexDump(packet.plain, "duz metin");
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Metin")) {
      const std::string text = asciiPreview(packet.plain.empty() ? packet.raw.data : packet.plain, 8192);
      ImGui::BeginChild("##text", ImVec2(0, 0), ImGuiChildFlags_Borders);
      ImGui::TextWrapped("%s", text.c_str());
      ImGui::EndChild();
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  ImGui::End();
}

void Ui::drawHexDump(const std::vector<std::uint8_t>& data, const char* caption) {
  ImGui::TextDisabled("%s: %zu bayt", caption, data.size());
  if (data.empty()) {
    ImGui::TextDisabled("(veri yok)");
    return;
  }

  ImGui::BeginChild("##hex", ImVec2(0, 0), ImGuiChildFlags_Borders);
  const int lineCount = static_cast<int>((data.size() + kHexBytesPerRow - 1) / kHexBytesPerRow);
  ImGuiListClipper clipper;
  clipper.Begin(lineCount, ImGui::GetTextLineHeightWithSpacing());
  while (clipper.Step()) {
    for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; ++line) {
      const std::size_t offset = static_cast<std::size_t>(line) * kHexBytesPerRow;
      const std::size_t count = std::min<std::size_t>(kHexBytesPerRow, data.size() - offset);

      char head[16];
      std::snprintf(head, sizeof(head), "%08zX  ", offset);
      ImGui::TextDisabled("%s", head);

      for (std::size_t i = 0; i < count; ++i) {
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::Text("%02X ", data[offset + i]);
      }

      ImGui::SameLine(0.0f, 8.0f);
      ImGui::TextDisabled("|");

      for (std::size_t i = 0; i < count; ++i) {
        const unsigned char c = data[offset + i];
        const bool printable = c >= 0x20 && c < 0x7F;
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, printable ? IM_COL32(214, 220, 232, 255) : IM_COL32(120, 126, 140, 255));
        ImGui::Text("%c", printable ? static_cast<char>(c) : '.');
        ImGui::PopStyleColor();
      }
    }
  }
  ImGui::EndChild();
}

void Ui::drawFieldTable(const std::vector<std::uint8_t>& plain) {
  constexpr std::size_t kMaxRows = 400;
  const std::size_t rowCount = std::min(plain.size(), kMaxRows);

  if (ImGui::BeginTable("##fields", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
    ImGui::TableSetupColumn("Ofset", ImGuiTableColumnFlags_WidthFixed, 64.0f);
    ImGui::TableSetupColumn("Yorumlanan", ImGuiTableColumnFlags_WidthFixed, 200.0f);
    ImGui::TableSetupColumn("Baytlar", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();

    for (std::size_t i = 0; i < rowCount; ++i) {
      const std::size_t available = plain.size() - i;
      const std::size_t width = std::min<std::size_t>(available, 4);
      const std::uint8_t* bytes = plain.data() + i;
      const std::size_t pairWidth = std::min<std::size_t>(width, 2);

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextDisabled("%04zu", i);
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("u16le=%u  u16be=%u", static_cast<unsigned>(readLE(bytes, pairWidth)),
                  static_cast<unsigned>(readBE(bytes, pairWidth)));
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(bytesToLowerHex(bytes, width).c_str());
    }
    ImGui::EndTable();
  }

  if (plain.size() > rowCount) {
    ImGui::TextDisabled("... ilk %zu bayt gosterildi, tamami hex sekmesinde.", rowCount);
  }
}

void Ui::drawWarningsPanel() {
  if (!showWarnings_) return;

  ImGui::Begin("Uyarilar");
  bool any = false;

  auto warn = [&any](const ImVec4& color, const char* text) {
    any = true;
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::TextWrapped("%s", text);
    ImGui::PopStyleColor();
  };

  if (!npcapPresent_) {
    warn(ImVec4(0.92f, 0.68f, 0.44f, 1.0f),
         "Npcap surucusu yok (wpcap.dll yuklenemiyor). Npcap kurup uygulamayi yeniden baslatin.");
  } else if (selectedDevice_ < 0) {
    warn(ImVec4(0.92f, 0.68f, 0.44f, 1.0f),
         "Listelenen ag adaptoru yok. Ag baglantisini kontrol edin, Yenile ile tekrar deneyin.");
  }

  if (!state_.error.empty()) {
    any = true;
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.93f, 0.49f, 0.49f, 1.0f));
    ImGui::TextWrapped("Son hata: %s", state_.error.c_str());
    ImGui::PopStyleColor();
  }

  if (!logError_.empty()) {
    any = true;
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.93f, 0.49f, 0.49f, 1.0f));
    ImGui::TextWrapped("Kayit hatasi: %s", logError_.c_str());
    ImGui::PopStyleColor();
  }

  if (capture_.running() && capture_.dropped() > 0) {
    any = true;
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.92f, 0.68f, 0.44f, 1.0f));
    ImGui::TextWrapped("Surucu %llu paket dusurdu; tampon yetersiz olabilir.",
                       static_cast<unsigned long long>(capture_.dropped()));
    ImGui::PopStyleColor();
  }

  if (!any) ImGui::TextDisabled("Sorun yok.");

  ImGui::Separator();
  ImGui::TextDisabled("Dinlenen portlar: TCP 15100-15109, 15001");
  if (pipeline_.hasClientKey()) ImGui::TextDisabled("Client anahtari ele gecirildi.");
  else ImGui::TextDisabled("Client anahtari bekleniyor (el sikisma).");

  ImGui::End();
}

void Ui::drawStatusBar() {
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(
      ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - kStatusBarHeight));
  ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, kStatusBarHeight));
  constexpr ImGuiWindowFlags kFlags =
      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

  ImGui::Begin("##statusbar", nullptr, kFlags);

  const bool running = capture_.running();
  const bool paused = buffer_.paused();
  const char* stateText = running ? (paused ? "Duraklatildi" : "Yakaliyor") : "Durduruldu";
  ImGui::TextColored(running ? ImVec4(0.51f, 0.84f, 0.56f, 1.0f) : ImVec4(0.60f, 0.62f, 0.66f, 1.0f), "Durum: %s",
                     stateText);

  ImGui::SameLine(0.0f, 12.0f);
  ImGui::TextDisabled("| Yakalanan: %llu  Dusan: %llu  Bekleyen: %zu",
                      static_cast<unsigned long long>(buffer_.capturedTotal()),
                      static_cast<unsigned long long>(buffer_.droppedTotal()), buffer_.pending());

  ImGui::SameLine(0.0f, 12.0f);
  ImGui::TextDisabled("| Tampon: %zu / %zu", rows_.size(), capacity_);

  ImGui::SameLine(0.0f, 12.0f);
  ImGui::TextDisabled("| Hiz: %.0f paket/s  Kare: %.2f ms", rate_, frameMs_);

  if (!state_.status.empty()) {
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextDisabled("| %s", state_.status.c_str());
  }

  ImGui::End();
}

} // namespace ko::ui
