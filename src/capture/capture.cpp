#include "capture/capture.h"

// pcap.h eski winsock.h'yi çekebiliyor; winsock2'yi önce alıp çakışmayı önle.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>

#include <pcap.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "capture/ethernet.h"

namespace ko {
namespace {

// Dinlenen trafik: KO oyun portları.
constexpr const char* kFilter = "tcp portrange 15100-15109 || port 15001";
constexpr int kSnapLen = 65535;
constexpr int kReadTimeoutMs = 100;
constexpr int kBufferSize = 64 * 1024 * 1024;

// Sürücü yoksa kullanıcıya gösterilecek metin.
constexpr const char* kNoDriver =
    "Npcap sürücüsü kurulu değil, npcap-1.90.exe ile kurun";

// wpcap.dll yüklü mü? Npcap kurulu değilse DLL de bulunmaz.
bool wpcapPresent() {
  HMODULE mod = ::LoadLibraryA("wpcap.dll");
  if (mod == nullptr) return false;
  ::FreeLibrary(mod);
  return true;
}

std::string lowerCopy(const std::string& s) {
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

// Cihaz listesindeki gürültü: loopback, uzak yakalama ve sanal/pseudo adaptörler.
bool isNoise(const pcap_if_t* dev) {
  if (dev == nullptr) return true;
  if ((dev->flags & PCAP_IF_LOOPBACK) != 0) return true;

  const std::string name = dev->name != nullptr ? lowerCopy(dev->name) : std::string();
  const std::string desc =
      dev->description != nullptr ? lowerCopy(dev->description) : std::string();

  if (name.rfind("rpcap://", 0) == 0) return true;

  static const char* const kNoiseParts[] = {
      "loopback",     "wan miniport",  "teredo",       "isatap",
      "bluetooth",    "wi-fi direct",  "kernel debug", "npcap packet",
  };
  for (const char* part : kNoiseParts) {
    if (desc.find(part) != std::string::npos) return true;
  }
  return false;
}

bool isConnected(const pcap_if_t* dev) {
  return dev != nullptr && (dev->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED) != 0;
}

// pcap_activate dönüşünü anlaşılır hata metnine çevirir.
std::string activationError(pcap_t* handle, int rc) {
  std::string msg;
  if (rc == PCAP_ERROR_NO_SUCH_DEVICE) {
    msg = "Cihaz bulunamadı (adaptör kaldırılmış olabilir)";
  } else if (rc == PCAP_ERROR_PERM_DENIED) {
    msg = "Erişim reddedildi, uygulamayı yönetici olarak çalıştırın";
  } else if (rc == PCAP_ERROR_IFACE_NOT_UP) {
    msg = "Cihaz hazır değil (bağlantı yok)";
  } else {
    msg = pcap_statustostr(rc);
  }

  const char* detail = pcap_geterr(handle);
  if (detail != nullptr && detail[0] != '\0') {
    msg += ": ";
    msg += detail;
  }
  return msg;
}

}  // namespace

struct Capture::Impl {
  pcap_t* handle = nullptr;
  std::thread worker;
  std::atomic<bool> stop_flag{false};
  std::atomic<bool> running_flag{false};
  std::function<void(RawPacket&&)> sink;
  std::mutex sink_mutex;
  std::mutex handle_mutex;
  net::LinkType frame_link = net::LinkType::Ethernet;
  // Son çözümleme hatası: aynı metni tekrar tekrar yazmamak için.
  const char* last_parse_error = nullptr;

  void resetState() {
    stop_flag.store(false, std::memory_order_relaxed);
    running_flag.store(false, std::memory_order_relaxed);
    last_parse_error = nullptr;
  }

  // Yakalama döngüsü; ayrı thread'de koşar.
  void loop() {
    for (;;) {
      if (stop_flag.load(std::memory_order_relaxed)) break;

      pcap_pkthdr* header = nullptr;
      const u_char* bytes = nullptr;
      const int rc = pcap_next_ex(handle, &header, &bytes);

      if (rc == 0) continue;              // okuma zaman aşımı: durdurma bayrağını yeniden kontrol et
      if (rc == PCAP_ERROR_BREAK) break;  // pcap_breakloop
      if (rc < 0) break;                  // sürücü hatası: döngüyü kır

      if (header == nullptr || bytes == nullptr) continue;
      if (header->caplen == 0) continue;

      net::ParsedFrame frame;
      if (!net::parseFrame(bytes, header->caplen, frame, frame_link)) {
        // Sessiz atlama yok: neden varsa son hata olarak saklanır ve hata metni
        // değiştiğinde hata ayıklayıcı çıktısına bir kez yazılır.
        if (frame.err != nullptr && last_parse_error != frame.err) {
          last_parse_error = frame.err;
          ::OutputDebugStringA("[KoPacketLogger] cerceve cozulemedi: ");
          ::OutputDebugStringA(frame.err);
          ::OutputDebugStringA("\n");
        }
        continue;
      }

      RawPacket packet;
      packet.ts_unix_us = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000 +
                          static_cast<std::int64_t>(header->ts.tv_usec);
      packet.dir = frame.dir;
      packet.data.assign(frame.payload, frame.payload + frame.payload_len);

      std::function<void(RawPacket&&)> local;
      {
        std::lock_guard<std::mutex> lock(sink_mutex);
        local = sink;
      }
      if (!local) continue;

      try {
        local(std::move(packet));
      } catch (...) {
        break;  // tüketici patlarsa istisnayı yut, döngüyü kır
      }
    }

    running_flag.store(false, std::memory_order_relaxed);
  }

  void closeHandle() {
    std::lock_guard<std::mutex> lock(handle_mutex);
    if (handle != nullptr) {
      pcap_close(handle);
      handle = nullptr;
    }
  }
};

Capture::Capture() : impl_(new Impl()) {}

Capture::~Capture() {
  stop();
  delete impl_;
  impl_ = nullptr;
}

std::vector<DeviceInfo> Capture::listDevices() {
  std::vector<DeviceInfo> result;
  if (!wpcapPresent()) return result;

  pcap_if_t* devices = nullptr;
  char errbuf[PCAP_ERRBUF_SIZE] = {};
  if (pcap_findalldevs(&devices, errbuf) != 0) return result;

  std::vector<const pcap_if_t*> usable;
  for (pcap_if_t* dev = devices; dev != nullptr; dev = dev->next) {
    if (isNoise(dev)) continue;
    usable.push_back(dev);
  }

  // Bağlı cihazlar önce, eşitlikte açıklamaya göre alfabetik.
  std::stable_sort(usable.begin(), usable.end(),
                   [](const pcap_if_t* a, const pcap_if_t* b) {
                     const bool ca = isConnected(a);
                     const bool cb = isConnected(b);
                     if (ca != cb) return ca;
                     const std::string da =
                         a->description != nullptr ? a->description : a->name;
                     const std::string db =
                         b->description != nullptr ? b->description : b->name;
                     return da < db;
                   });

  result.reserve(usable.size());
  for (const pcap_if_t* dev : usable) {
    DeviceInfo info;
    info.name = dev->name != nullptr ? dev->name : std::string();
    info.description = dev->description != nullptr ? dev->description : info.name;
    if (info.name.empty()) continue;
    result.push_back(std::move(info));
  }

  pcap_freealldevs(devices);
  return result;
}

bool Capture::start(const std::string& device, std::string& err) {
  if (impl_ == nullptr) {
    err = "Yakalama nesnesi hazır değil";
    return false;
  }
  if (impl_->running_flag.load(std::memory_order_relaxed)) {
    err = "Yakalama zaten çalışıyor";
    return false;
  }
  if (device.empty()) {
    err = "Cihaz seçilmedi";
    return false;
  }

  stop();  // önceki oturum artığı varsa temizle
  impl_->resetState();

  if (!wpcapPresent()) {
    err = kNoDriver;
    return false;
  }

  char errbuf[PCAP_ERRBUF_SIZE] = {};
  pcap_t* handle = pcap_create(device.c_str(), errbuf);
  if (handle == nullptr) {
    err = "Yakalama oturumu açılamadı";
    if (errbuf[0] != '\0') {
      err += ": ";
      err += errbuf;
    } else {
      err += ", ";
      err += kNoDriver;
    }
    return false;
  }

  // Buffer boyutu kritik değil; başarısız olursa varsayılanda devam.
  pcap_set_buffer_size(handle, kBufferSize);
  pcap_set_snaplen(handle, kSnapLen);
  pcap_set_promisc(handle, 1);
  pcap_set_timeout(handle, kReadTimeoutMs);
  pcap_setmintocopy(handle, 65536);

  const int rc = pcap_activate(handle);
  if (rc < 0) {
    err = activationError(handle, rc);
    pcap_close(handle);
    return false;
  }

  // Çözümleyici Ethernet, Raw IP, loopback ve ham 802.11 (radiotap dahil)
  // çerçevelerini biliyor. Başka link tipinde sessizce paket kaybetmek yerine
  // açık hata ver.
  const int link_type = pcap_datalink(handle);
  net::LinkType frame_link = net::LinkType::Ethernet;
  if (link_type == DLT_EN10MB) {
    frame_link = net::LinkType::Ethernet;
  } else if (link_type == DLT_RAW) {
    frame_link = net::LinkType::RawIp;
  } else if (link_type == DLT_NULL || link_type == DLT_LOOP) {
    frame_link = net::LinkType::NullLoop;
  } else if (link_type == DLT_IEEE802_11) {
    frame_link = net::LinkType::Dot11;
  } else if (link_type == DLT_IEEE802_11_RADIO) {
    frame_link = net::LinkType::Dot11Radio;
  } else {
    const char* link_name = pcap_datalink_val_to_description(link_type);
    err = "Desteklenmeyen link tipi (DLT=" + std::to_string(link_type) + "): " +
          (link_name != nullptr ? link_name : "bilinmiyor");
    pcap_close(handle);
    return false;
  }

  bpf_program program{};
  if (pcap_compile(handle, &program, kFilter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
    err = "BPF filtresi derlenemedi: ";
    err += pcap_geterr(handle);
    pcap_close(handle);
    return false;
  }
  const int set_rc = pcap_setfilter(handle, &program);
  pcap_freecode(&program);
  if (set_rc != 0) {
    err = "BPF filtresi uygulanamadı: ";
    err += pcap_geterr(handle);
    pcap_close(handle);
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(impl_->handle_mutex);
    impl_->handle = handle;
  }
  impl_->frame_link = frame_link;

  impl_->running_flag.store(true, std::memory_order_relaxed);
  try {
    impl_->worker = std::thread([this] { impl_->loop(); });
  } catch (...) {
    impl_->running_flag.store(false, std::memory_order_relaxed);
    impl_->closeHandle();
    err = "Yakalama thread'i başlatılamadı";
    return false;
  }
  return true;
}

void Capture::stop() {
  if (impl_ == nullptr) return;

  impl_->stop_flag.store(true, std::memory_order_relaxed);
  {
    std::lock_guard<std::mutex> lock(impl_->handle_mutex);
    if (impl_->handle != nullptr) pcap_breakloop(impl_->handle);
  }

  if (impl_->worker.joinable()) impl_->worker.join();

  impl_->running_flag.store(false, std::memory_order_relaxed);
  impl_->closeHandle();
}

bool Capture::running() const {
  if (impl_ == nullptr) return false;
  return impl_->running_flag.load(std::memory_order_relaxed);
}

void Capture::setSink(std::function<void(RawPacket&&)> sink) {
  if (impl_ == nullptr) return;
  std::lock_guard<std::mutex> lock(impl_->sink_mutex);
  impl_->sink = std::move(sink);
}

std::uint64_t Capture::dropped() const {
  if (impl_ == nullptr) return 0;

  pcap_stat stats{};
  {
    std::lock_guard<std::mutex> lock(impl_->handle_mutex);
    if (impl_->handle == nullptr) return 0;
    if (pcap_stats(impl_->handle, &stats) != 0) return 0;
  }
  return static_cast<std::uint64_t>(stats.ps_drop);
}

}  // namespace ko
