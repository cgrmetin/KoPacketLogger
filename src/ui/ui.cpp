#include "ui/ui.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <string>

#include "imgui.h"
#include "imgui_internal.h"

#include "ui/theme.h"

namespace ko::ui {
namespace {

// Toolbar ve durum cubugu sabittir; dockspace araligi bunlara gore hesaplanir.
constexpr float kToolbarHeight = 68.0f;
constexpr float kStatusBarHeight = 26.0f;

// Hex dump satir uzunlugu.
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

// Unix mikrosaniyeyi saat:dakika:saniye.milisaniye bicimine cevirir.
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

// Baytlari yazdirilabilir ASCII'ye cevirir; okunamaz yerlerde nokta kullanir.
std::string asciiPreview(const std::vector<std::uint8_t>& data, std::size_t maxChars) {
  std::string out;
  const std::size_t limit = std::min<std::size_t>(data.size(), maxChars);
  out.reserve(limit);
  for (std::size_t i = 0; i < limit; ++i) {
    const unsigned char c = data[i];
    out.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '.');
  }
  if (data.size() > limit) {
    out += "...";
  }
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
  for (std::size_t i = 0; i < count; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
  }
  return value;
}

std::uint64_t readBE(const std::uint8_t* data, std::size_t count) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < count; ++i) {
    value = (value << 8) | data[i];
  }
  return value;
}

// Kisa bir bayt serisinden okunabilir ozet: ilk degerlerin hex ve sayisal onizlemesi.
std::string summarize(const DecodedPacket& packet) {
  const std::vector<std::uint8_t>& data = packet.plain.empty() ? packet.raw.data : packet.plain;
  if (data.empty()) return "(bos)";
  std::string out = bytesToLowerHex(data.data(), std::min<std::size_t>(data.size(), 8));
  if (data.size() >= 2) {
    char tail[64];
    std::snprintf(tail, sizeof(tail), "   [%u..%u]", static_cast<unsigned>(readLE(data.data(), 2) >> 8),
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
  logPath_ = "logs";
}

Ui::~Ui() { stopCapture(); }

void Ui::initialize() {
  refreshDevices();
  if (!npcapPresent_) {
    setError("Npcap surucusu kurulu degil. Npcap surucusu (npcap-1.90.exe) kurulduktan "
             "sonra uygulama yeniden baslatilmalidir.");
  } else if (selectedDevice_ < 0) {
    setError("Kullanilabilir ag adaptoru bulunamadi. Ag baglantisi var mi kontrol edin.");
  } else {
    setStatus("Hazir. Yakalamak icin Baslat'a basin.");
  }
}

// ---------------------------------------------------------------------------
// Veri akisi
// ---------------------------------------------------------------------------

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
  for (RawPacket& raw : drainScratch_) {
    pipeline_.process(raw, decodeScratch_);
  }

  const bool filtersActive = prepared_.showIn && prepared_.showOut && !prepared_.errorsOnly &&
                             !prepared_.opcodeRange && !prepared_.nameContains && !prepared_.sizeRange &&
                             !prepared_.text;
  for (DecodedPacket& decoded : decodeScratch_) {
    const std::uint64_t seq = nextSeq_++;
    const bool accepted = filtersActive || prepared_.matches(decoded);
    appendDecoded(std::move(decoded), seq, accepted);
  }

  evictOverflow();
}

void Ui::appendDecoded(DecodedPacket&& packet, std::uint64_t seq, bool accepted) {
  Row row;
  row.seq = seq;
  row.packet = std::move(packet);
  rows_.push_back(std::move(row));
  if (accepted) {
    filtered_.push_back(seq);
  }
}

void Ui::evictOverflow() {
  while (rows_.size() > capacity_) {
    const std::uint64_t droppedSeq = rows_.front().seq;
    rows_.pop_front();
    if (filtered_.front() == droppedSeq) {
      filtered_.erase(filtered_.begin());
    } else {
      // Filtreli liste bastan kopmus olabilir; boyle bir durumda yeniden kur.
      filtersDirty_ = true;
    }
    if (selectedSeq_ == droppedSeq) selectedSeq_ = 0;
  }
}

void Ui::rebuildFiltered() {
  filtered_.clear();
  const bool filtersActive = prepared_.showIn && prepared_.showOut && !prepared_.errorsOnly &&
                             !prepared_.opcodeRange && !prepared_.nameContains && !prepared_.sizeRange &&
                             !prepared_.text;
  for (const Row& row : rows_) {
    if (filtersActive || prepared_.matches(row.packet)) {
      filtered_.push_back(row.seq);
    }
  }
  if (!filtered_.empty() && std::find(filtered_.begin(), filtered_.end(), selectedSeq_) == filtered_.end()) {
    selectedSeq_ = 0;
  }
  filtersDirty_ = false;
}

const Row* Ui::selectedRow() const {
  if (selectedSeq_ == 0) return nullptr;
  for (const Row& row : rows_) {
    if (row.seq == selectedSeq_) return &row;
  }
  return nullptr;
}

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
  if (capture_.running()) return;
  if (selectedDevice_ < 0) {
    setError("Once bir ag adaptoru secin.");
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
  clear_error();
  setStatus("Yakalama devam ediyor.");
}

void Ui::stopCapture() {
  if (!capture_.running()) {
    state_.capturing.store(false, std::memory_order_relaxed);
    return;
  }
  capture_.stop();
  state_.capturing.store(false, std::memory_order_relaxed);
  setStatus("Yakalama durduruldu.");
}

void Ui::togglePause() {
  const bool paused = !buffer_.paused();
  buffer_.setPaused(paused);
  setStatus(paused ? "Yakalama duraklatildi; gelen paketler birakiliyor." : "Yakalama suruyor.");
}

void Ui::clearPackets() {
  rows_.clear();
  filtered_.clear();
  selectedSeq_ = 0;
  nextSeq_ = 1;
  filtersDirty_ = true;
  setStatus("Paket listesi temizlendi.");
}

void Ui::toggleLogging() {
  if (log_.isOpen()) {
    log_.close();
    logError_.clear();
    setStatus("Kayit kapatildi: " + log_.path());
    return;
  }

  if (!std::filesystem::exists(logPath_)) {
    std::error_code ec;
    std::filesystem::create_directories(logPath_, ec);
  }

  std::time_t now = std::time(nullptr);
  std::tm local{};
  localtime_s(&local, &now);
  char name[64];
  std::snprintf(name, sizeof(name), "ko-%04d%02d%02d-%02d%02d%02d.log", local.tm_year + 1900, local.tm_mon + 1,
                local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
  const std::string path = logPath_ + "/" + name;

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
// Cizim
// ---------------------------------------------------------------------------

void Ui::frame() {
  pumpCapture();

  if (filtersDirty_) {
    PreparedFilter fresh = prepare(filters_);
    if (!fresh.sameAs(prepared_)) {
      prepared_ = std::move(fresh);
    }
    rebuildFiltered();
  }

  const double now = ImGui::GetTime();
  if (lastFrameTime_ > 0.0) {
    frameMs_ = static_cast<float>((now - lastFrameTime_) * 1000.0);
  }
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
  const ImVec2 dockPos(viewport->WorkPos.x, viewport->WorkPos.y + kToolbarHeight);
  const ImVec2 dockSize(viewport->WorkSize.x,
                        viewport->WorkSize.y - kToolbarHeight - kStatusBarHeight);
  const ImGuiID dockspaceId = ImGui::GetID("KoDockspace");

  ImGui::DockSpace(dockspaceId, dockSize, ImGuiDockNodeFlags_None);

  if (!layoutBuilt_) {
    layoutBuilt_ = true;
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, dockSize);

    ImGuiID left = dockspaceId;
    ImGuiID right = dockspaceId;
    ImGui::DockBuilderSplitNode(left, ImGuiDir_Left, 0.62f, nullptr, &right);
    ImGuiID bottom = right;
    ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.28f, nullptr, &bottom);

    ImGui::DockBuilderDockWindow("Paket Listesi", left);
    ImGui::DockBuilderDockWindow("Paket Detayı", bottom);
    ImGui::DockBuilderDockWindow("Uyarılar", right);
    ImGui::DockBuilderFinish(dockspaceId);
  }
}

void Ui::drawMenuBarAndToolbar() {
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, kToolbarHeight));
  constexpr ImGuiWindowFlags kFlags =
      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoScrollbar;

  if (!ImGui::Begin("##toolbar", nullptr, kFlags)) {
    ImGui::End();
    return;
  }

  if (ImGui::BeginMenuBar()) {
    if (ImGui::BeginMenu("Dosya")) {
      if (ImGui::MenuItem(log_.isOpen() ? "Kaydı Kapat" : "Kaydı Aç")) toggleLogging();
      ImGui::Separator();
      if (ImGui::MenuItem("Çıkış")) state_.quit.store(true, std::memory_order_relaxed);
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Görünüm")) {
      if (ImGui::MenuItem("Otomatik Kaydır", nullptr, autoScroll_)) autoScroll_ = !autoScroll_;
      if (ImGui::MenuItem("Uyarılar", nullptr, showWarnings_)) showWarnings_ = !showWarnings_;
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Yakalama")) {
      if (ImGui::MenuItem("Başlat", nullptr, false, selectedDevice_ >= 0 && !capture_.running())) startCapture();
      if (ImGui::MenuItem("Durdur", nullptr, false, capture_.running())) stopCapture();
      if (ImGui::MenuItem("Duraklat / Devam", nullptr, false, capture_.running())) togglePause();
      ImGui::Separator();
      if (ImGui::MenuItem("Temizle")) clearPackets();
      ImGui::EndMenu();
    }
    ImGui::EndMenuBar();
  }

  // --- Adaptör seçimi ---
  ImGui::AlignTextToFramePadding();
  ImGui::TextUnformatted("Adaptör:");
  ImGui::SameLine();
  {
    std::vector<DeviceInfo> devices;
    {
      std::lock_guard<std::mutex> lock(state_.devicesMutex);
      devices = state_.devices;
    }

    const char* preview = devices.empty() ? "(adaptör yok)"
                                          : devices[static_cast<std::size_t>(selectedDevice_)].description.c_str();
    ImGui::SetNextItemWidth(320.0f);
    if (ImGui::BeginCombo("##device", preview)) {
      for (int i = 0; i < static_cast<int>(devices.size()); ++i) {
        const bool selected = (i == selectedDevice_);
        const std::string label = devices[static_cast<std::size_t>(i)].description;
        if (ImGui::Selectable(label.c_str(), selected)) {
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
      setStatus("Adaptör listesi yenilendi.");
    }
  }

  ImGui::SameLine(0.0f, 12.0f);

  // --- Başlat / Durdur ---
  {
    const bool running = capture_.running();
    if (!running) {
      if (ImGui::Button("▶ Başlat", ImVec2(92.0f, 0.0f))) startCapture();
      ImGui::SameLine();
      if (ImGui::Button("⏸ Duraklat", ImVec2(96.0f, 0.0f)) && false) {
      }
    } else {
      if (ImGui::Button("■ Durdur", ImVec2(92.0f, 0.0f))) stopCapture();
      ImGui::SameLine();
      const bool paused = buffer_.paused();
      if (ImGui::Button(paused ? "▶ Devam" : "⏸ Duraklat", ImVec2(96.0f, 0.0f))) togglePause();
    }
    ImGui::SameLine();
    if (ImGui::Button("Temizle", ImVec2(80.0f, 0.0f))) clearPackets();
    ImGui::SameLine();
    if (ImGui::Button(log_.isOpen() ? "⏺ Kayıt: Açık" : "⏺ Kayıt: Kapalı")) toggleLogging();
    if (log_.isOpen()) {
      ImGui::SameLine();
      ImGui::TextDisabled("%llu", static_cast<unsigned long long>(log_.writtenCount()));
    }
  }

  ImGui::SameLine(0.0f, 12.0f);

  // --- Arama ---
  ImGui::SetNextItemWidth(240.0f);
  if (ImGui::InputTextWithHint("##search", "Ara (opcode, hex, metin)", filters_.text, sizeof(filters_.text))) {
    filtersDirty_ = true;
  }

  ImGui::End();
}

void Ui::drawPacketList() {
  if (!ImGui::Begin("Paket Listesi")) {
    ImGui::End();
    return;
  }

  drawFilterBar();

  const float listHeight = ImGui::GetContentRegionAvail().y;
  if (listHeight <= 0.0f) {
    ImGui::End();
    return;
  }

  if (ImGui::BeginTable("##packets", 7,
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable |
                            ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                            ImGuiTableFlags_SizingStretchProp,
                        ImVec2(0.0f, listHeight))) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Sıra", ImGuiTableColumnFlags_WidthFixed, 58.0f);
    ImGui::TableSetupColumn("Saat (ms)", ImGuiTableColumnFlags_WidthFixed, 96.0f);
    ImGui::TableSetupColumn("Yön", ImGuiTableColumnFlags_WidthFixed, 62.0f);
    ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 62.0f);
    ImGui::TableSetupColumn("Ad", ImGuiTableColumnFlags_WidthStretch, 160.0f);
    ImGui::TableSetupColumn("Boyut", ImGuiTableColumnFlags_WidthFixed, 66.0f);
    ImGui::TableSetupColumn("Özet", ImGuiTableColumnFlags_WidthStretch, 220.0f);
    ImGui::TableHeadersRow();

    // seq -> satir arama: deque bastan tuketildigi icin verimli bir ileri/geri isaretci tut.
    const int total = static_cast<int>(filtered_.size());
    ImGuiListClipper clipper;
    clipper.Begin(total, static_cast<float>(ImGui::GetTextLineHeightWithSpacing()));
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const std::uint64_t seq = filtered_[static_cast<std::size_t>(row)];
        const Row* rowPtr = nullptr;
        for (const Row& candidate : rows_) {
          if (candidate.seq == seq) {
            rowPtr = &candidate;
            break;
          }
        }
        if (rowPtr == nullptr) continue;

        const DecodedPacket& packet = rowPtr->packet;
        const bool incoming = packet.raw.dir == Direction::In;
        const bool known = ko::isKnownOpcode(packet.opcode);

        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(seq & 0x7FFFFFFF));

        ImGui::TableSetColumnIndex(0);
        const bool selected = (rowPtr->seq == selectedSeq_);
        if (ImGui::Selectable("##sel", selected,
                              ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
          selectRow(rowPtr->seq);
        }

        ImGui::SameLine();
        ImGui::TextDisabled("%llu", static_cast<unsigned long long>(seq));

        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(clockString(packet.raw.ts_unix_us).c_str());

        ImGui::TableSetColumnIndex(2);
        ImGui::PushStyleColor(ImGuiCol_Text, colorForDirection(incoming));
        ImGui::TextUnformatted(directionLabel(packet.raw.dir));
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(3);
        if (!packet.ok) {
          ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 120, 120));
        } else if (!known) {
          ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 170, 110));
        }
        ImGui::Text("0x%02X", packet.opcode);
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(4);
        ImGui::TextUnformatted(packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN");

        ImGui::TableSetColumnIndex(5);
        ImGui::Text("%zu", packet.raw.data.size());

        ImGui::TableSetColumnIndex(6);
        if (!packet.ok) {
          ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 120, 120));
          ImGui::TextUnformatted(packet.error.c_str());
          ImGui::PopStyleColor();
        } else {
          ImGui::TextUnformatted(summarize(packet).c_str());
        }

        ImGui::PopID();
      }
    }
    ImGui::EndTable();
  }

  ImGui::End();
}

void Ui::drawFilterBar() {
  ImGui::AlignTextToFramePadding();
  ImGui::Text("Filtre");
  ImGui::SameLine();
  if (ImGui::SmallButton(filterBarOpen_ ? " Gizle" : " Göster")) {
    filterBarOpen_ = !filterBarOpen_;
  }
  ImGui::SameLine();
  ImGui::TextDisabled("|  Sonuç: %zu / %zu paket", filtered_.size(), rows_.size());

  if (!filterBarOpen_) return;

  if (ImGui::BeginTable("##filters", 4, ImGuiTableFlags_SizingStretchProp)) {
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    if (ImGui::Checkbox("Gelen", &filters_.showIn)) filtersDirty_ = true;
    ImGui::SameLine();
    if (ImGui::Checkbox("Giden", &filters_.showOut)) filtersDirty_ = true;
    ImGui::SameLine();
    if (ImGui::Checkbox("Sadece Hatalılar", &filters_.errorsOnly)) filtersDirty_ = true;

    ImGui::TableSetColumnIndex(1);
    ImGui::SetNextItemWidth(110.0f);
    if (ImGui::InputInt("##opmin", &filters_.opcodeMin)) filtersDirty_ = true;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.0f);
    if (ImGui::InputInt("##opmax", &filters_.opcodeMax)) filtersDirty_ = true;
    ImGui::SameLine();
    ImGui::TextDisabled("opcode aralığı (0-255)");

    ImGui::TableSetColumnIndex(2);
    ImGui::SetNextItemWidth(110.0f);
    if (ImGui::InputInt("##szmin", &filters_.sizeMin)) filtersDirty_ = true;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.0f);
    if (ImGui::InputInt("##szmax", &filters_.sizeMax)) filtersDirty_ = true;
    ImGui::SameLine();
    ImGui::TextDisabled("boyut aralığı (bayt)");

    ImGui::TableSetColumnIndex(3);
    ImGui::SetNextItemWidth(220.0f);
    if (ImGui::InputTextWithHint("##namefilter", "Opcode adı içerecek", filters_.nameContains,
                                 sizeof(filters_.nameContains))) {
      filtersDirty_ = true;
    }

    ImGui::EndTable();
  }
}

void Ui::drawDetailPanel() {
  if (!ImGui::Begin("Paket Detayı")) {
    ImGui::End();
    return;
  }

  const Row* row = selectedRow();
  if (row == nullptr) {
    ImGui::TextDisabled("Ayrıntı için soldaki listeden bir paket seçin.");
    ImGui::End();
    return;
  }

  const DecodedPacket& packet = row->packet;
  const bool incoming = packet.raw.dir == Direction::In;

  if (ImGui::BeginTable("##summary", 2, kDetailTableFlags)) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Sıra");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", static_cast<unsigned long long>(row->seq));

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Saat");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(clockString(packet.raw.ts_unix_us).c_str());

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Yön");
    ImGui::TableSetColumnIndex(1);
    ImGui::PushStyleColor(ImGuiCol_Text, colorForDirection(incoming));
    ImGui::TextUnformatted(directionLabel(packet.raw.dir));
    ImGui::PopStyleColor();

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Kripto");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(cryptionLabel(packet.cryption));

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Opcode");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("0x%02X (%u)  %s", packet.opcode, static_cast<unsigned>(packet.opcode),
                packet.opcode_name != nullptr ? packet.opcode_name : "UNKNOWN");

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Uzunluk");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%zu bayt", packet.raw.data.size());

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Çözülmüş");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%zu bayt", packet.plain.size());

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Durum");
    ImGui::TableSetColumnIndex(1);
    if (packet.ok) {
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(150, 220, 160));
      ImGui::TextUnformatted("Başarılı");
    } else {
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 120, 120));
      ImGui::TextUnformatted(packet.error.c_str());
    }
    ImGui::PopStyleColor();

    ImGui::EndTable();
  }

  if (!packet.ok && !packet.error.empty()) {
    ImGui::Separator();
    ImGui::TextColored(ImVec4(0.92f, 0.47f, 0.47f, 1.0f), "Hata: %s", packet.error.c_str());
  }

  ImGui::Separator();
  if (ImGui::BeginTabBar("##detailtabs")) {
    if (ImGui::BeginTabItem("Ham Hex")) {
      drawHexDump(packet.raw.data, "ham");
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Çözülmüş Gövde")) {
      if (packet.plain.empty()) {
        ImGui::TextDisabled("Çözülmüş gövde yok.");
      } else {
        ImGui::TextDisabled("İlk bayt opcode = 0x%02X; kalan baytlar gövde alanlarıdır.", packet.opcode);
        drawFieldTable(packet.plain);
        ImGui::Separator();
        drawHexDump(packet.plain, "düz");
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Metin")) {
      const std::string text = asciiPreview(packet.plain.empty() ? packet.raw.data : packet.plain, 4096);
      ImGui::BeginChild("##text", ImVec2(0, 0), ImGuiChildFlags_Borders);
      ImGui::TextWrapped("%s", text.c_str());
      ImGui::EndChild();
      ImGui::EndTabItem();
    }
    ImGui::EndTabItem();
  }

  ImGui::End();
}

void Ui::drawHexDump(const std::vector<std::uint8_t>& data, const char* caption) {
  ImGui::TextDisabled("%s: %zu bayt", caption, data.size());
  if (data.empty()) {
    ImGui::TextDisabled("(veri yok)");
    return;
  }

  const float height = ImGui::GetContentRegionAvail().y;
  if (height <= 0.0f) return;

  ImGui::BeginChild("##hex", ImVec2(0, 0), ImGuiChildFlags_Borders);
  const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
  ImGuiListClipper clipper;
  clipper.Begin(static_cast<int>((data.size() + kHexBytesPerRow - 1) / kHexBytesPerRow), lineHeight);
  while (clipper.Step()) {
    for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; ++line) {
      const std::size_t offset = static_cast<std::size_t>(line) * kHexBytesPerRow;
      const std::size_t count = std::min<std::size_t>(kHexBytesPerRow, data.size() - offset);

      char head[16];
      std::snprintf(head, sizeof(head), "%08zX  ", offset);
      ImGui::TextDisabled("%s", head);
      ImGui::SameLine(0, 0);

      for (std::size_t i = 0; i < count; ++i) {
        ImGui::Text("%02X ", data[offset + i]);
        if (i + 1 != count) ImGui::SameLine(0, 0);
      }

      ImGui::SameLine(0, 8);
      ImGui::TextDisabled("|");
      ImGui::SameLine(0, 6);
      for (std::size_t i = 0; i < count; ++i) {
        const unsigned char c = data[offset + i];
        const bool printable = c >= 0x20 && c < 0x7F;
        if (!printable) {
          ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(120, 126, 140));
        }
        ImGui::Text("%c", printable ? static_cast<char>(c) : '.');
        if (!printable) ImGui::PopStyleColor();
        if (i + 1 != count) ImGui::SameLine(0, 0);
      }
    }
  }
  ImGui::EndChild();
}

void Ui::drawFieldTable(const std::vector<std::uint8_t>& plain) {
  if (ImGui::BeginTable("##fields", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
    ImGui::TableSetupColumn("Ofset", ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableSetupColumn("Sayısal Değer", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Baytlar", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();

    // Her ofset için 1, 2 ve 4 bayt okumalarini goster; karar vericinin gorevi degil,
    // sadece teşhis için hızlı bir bakış sunar.
    for (std::size_t i = 0; i < plain.size(); ++i) {
      const std::size_t available = plain.size() - i;
      const int width = available >= 4 ? 4 : (available >= 2 ? 2 : 1);
      const std::uint8_t* bytes = plain.data() + i;

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextDisabled("%04zu", i);
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("u16le=%u  u16be=%u", static_cast<unsigned>(readLE(bytes, std::min<std::size_t>(width, 2))),
                  static_cast<unsigned>(readBE(bytes, std::min<std::size_t>(width, 2))));
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(bytesToLowerHex(bytes, static_cast<std::size_t>(width)).c_str());

      if (i > 512) break;  // tablo icin yeterli; tum govde ayrica hex dump'ta
    }
    ImGui::EndTable();
  }
}

void Ui::drawWarningsPanel() {
  if (!showWarnings_) return;

  if (!ImGui::Begin("Uyarılar")) {
    ImGui::End();
    return;
  }

  bool hasWarning = false;

  if (!npcapPresent_) {
    hasWarning = true;
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 170, 110));
    ImGui::TextWrapped(
        "Npcap sürücüsü bulunamadı (wpcap.dll yüklenemiyor). Paket yakalama çalışmayacak. "
        "Npcap sürümünü (npcap-1.90.exe) kurup uygulamayı yeniden başlatın.");
    ImGui::PopStyleColor();
  } else if (selectedDevice_ < 0) {
    hasWarning = true;
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 170, 110));
    ImGui::TextWrapped(
        "Kullanılabilir bir ağ adaptörü listelenemedi. Ağ bağlantınızı kontrol edin ve "
        "Yenile düğmesiyle adaptör listesini tazeleyin.");
    ImGui::PopStyleColor();
  }

  if (!state_.error.empty()) {
    hasWarning = true;
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 120, 120));
    ImGui::TextWrapped("Son hata: %s", state_.error.c_str());
    ImGui::PopStyleColor();
  }

  if (!logError_.empty()) {
    hasWarning = true;
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 120, 120));
    ImGui::TextWrapped("Kayıt dosyası hatası: %s", logError_.c_str());
    ImGui::PopStyleColor();
  }

  if (capture_.dropped() > 0) {
    hasWarning = true;
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 170, 110));
    ImGui::TextWrapped("Yakalama sürücüsü %llu paketi düşürdü; arabellek yetersiz olabilir.",
                       static_cast<unsigned long long>(capture_.dropped()));
    ImGui::PopStyleColor();
  }

  if (!hasWarning) {
    ImGui::TextDisabled("Sorun yok. Adaptör ve sürücü hazır.");
  }

  ImGui::End();
}

void Ui::drawStatusBar() {
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - kStatusBarHeight));
  ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, kStatusBarHeight));
  constexpr ImGuiWindowFlags kFlags =
      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

  if (!ImGui::Begin("##statusbar", nullptr, kFlags)) {
    ImGui::End();
    return;
  }

  const bool running = capture_.running();
  const bool paused = buffer_.paused();

  ImGui::TextColored(running ? ImVec4(0.50f, 0.84f, 0.56f, 1.0f) : ImVec4(0.60f, 0.62f, 0.66f, 1.0f),
                     "Durum: %s", running ? (paused ? "Duraklatıldı" : "Yakalıyor") : "Durduruldu");
  ImGui::SameLine(0, 12);
  ImGui::TextDisabled("|  Yakalanan: %llu   Düşen: %llu   Bekleyen: %zu", static_cast<unsigned long long>(buffer_.capturedTotal()),
                      static_cast<unsigned long long>(buffer_.droppedTotal()), buffer_.pending());
  ImGui::SameLine(0, 12);
  ImGui::TextDisabled("|  Listede: %zu paket (arabellek %zu)", rows_.size(), capacity_);
  ImGui::SameLine(0, 12);
  ImGui::TextDisabled("|  Hız: %.0f paket/sn   Kare: %.2f ms", rate_, frameMs_);

  if (!state_.status.empty()) {
    ImGui::SameLine(0, 12);
    ImGui::TextDisabled("|  %s", state_.status.c_str());
  }

  ImGui::End();
}

} // namespace ko::ui
