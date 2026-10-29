# KoPacketLogger

Knight Online istemci/sunucu TCP trafiğini yakalayıp çözen ve opcode bazında
gösteren native bir araç. Eski C# (WinForms + SharpPcap) uygulamasının C++23
karşılığı.

## Durum

- `src/core` — AES-128-CBC çözme, çerçeve ayrıştırma (stream reassembly),
  WIZ opcode tablosu, `RawPacket -> DecodedPacket` çözücü. **Bağımsız**, UI'ya
  bağımlılığı yok.
- `src/capture` — Npcap ile paket yakalama ve Ethernet/IP/TCP ayrıştırma.
- `src/ui` — filtre, paket tamponu, log yazıcı, tema.
- `src/main.cpp`, `src/app.h` — uygulama girişi ve ortak durum.
- UI çizimi Dear ImGui ile yapılır (`third_party/imgui`).

Legacy C# kodu `legacy-csharp` dalında ve `v0.1-csharp-legacy` etiketinde
saklıdır.

## Gereksinimler

| Bileşen | Sürüm |
|---|---|
| Visual Studio | 18 (2026), "Desktop development with C++" iş yükü |
| MSVC toolset | v145, x64 |
| CMake | 3.28+ (VS içindeki CMake yeterli) |
| Npcap | **çalışma zamanında kurulu olmalı** (WinPcap uyumluluk modu) |

Npcap SDK repoda `third_party/npcap-sdk-1.17` altında gelir; ayrıca indirmeye
gerek yok. Derleme statik CRT (`/MT`) ile yapılır, tek `exe` üretilir.

## Derleme

```powershell
.\build.ps1                # Release
.\build.ps1 -Config Debug  # Debug
.\build.ps1 -Clean         # build/ dizinini sil, baştan yapılandır
```

Betik sırayla `cmake`i PATH'te, VS 18 kurulumunda ve `vswhere` üzerinden arar;
derleme ortamını `vcvars64.bat` ile kurar. Çıktı: `build/out/`.

Elle:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
    -S . -B build -G "Visual Studio 18 2026" -A x64
& '...\cmake.exe' --build build --config Release
```

## Çalıştırma

1. **Npcap** kurulu olmalı (kurulum sırasında "WinPcap API-compatible Mode"
   seçili olsun).
2. Uygulamayı **yönetici olarak** çalıştırın; ham soket yakalama aksi halde
   başarısız olur.
3. Arayüzden ağ adaptörünü seçin ve yakalamayı başlatın.

Varsayılan BPF filtresi `tcp portrange 15100-15109 || port 15001`.

## Protokol özeti

- Çerçeve: `[0..1]` big-endian uzunluk, `[2]` kripto türü (`0x01` client,
  `0x02` server, `0x16` handshake), ardından gövde ve 2 byte kuyruk.
- Şifreleme: AES-128-CBC + PKCS7, sabit IV.
- Server anahtarı sabittir; client anahtarı handshake çerçevesinden okunur.
- Opcode konumu yöne göre kayar: gelen pakette `plain[0]`, giden pakette
  `plain[1]`. Bu varsayım IDA analiziyle doğrulanacak.

Ayrıntılar: `D:\MyBrain\projects\KoPacketLogger\protokol-notlari.md`.

## Uyarı

Bu araç yalnızca kendi bağlantınızı incelemek için kullanılmalıdır. Başkasının
trafiğini izlemek bulunduğunuz yerde suç olabilir.
