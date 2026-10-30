# KoPacketLogger

Knight Online istemci/sunucu TCP trafiğini yakalayıp çözen ve opcode bazında
gösteren native bir araç.

## Durum

- `src/core` — AES-128-CBC çözme, çerçeve ayrıştırma (stream reassembly),
  WIZ opcode tablosu, `RawPacket -> DecodedPacket` çözücü. **Bağımsız**, UI'ya
  bağımlılığı yok.
- `src/capture` — Npcap ile paket yakalama, Ethernet/IP/TCP ve 802.11
  ayrıştırma.
- `src/ui` — filtre, paket tamponu, log yazıcı, tema.
- `src/main.cpp`, `src/app.h` — uygulama girişi ve ortak durum.
- UI çizimi Dear ImGui ile yapılır (`third_party/imgui`).

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

## Çalıştırma

1. **Npcap** kurulu olmalı (kurulum sırasında "WinPcap API-compatible Mode"
   seçili olsun).
2. Uygulamayı **yönetici olarak** çalıştırın; manifest `requireAdministrator`
   taşır, UAC onayı ister.
3. Arayüzden ağ adaptörünü seçin ve yakalamayı başlatın.

Varsayılan BPF filtresi `tcp portrange 15100-15109 || port 15001`.

## Protokol özeti

- Çerçeve: `AA 55 | uint16 LE gövde uzunluğu | gövde | 55 AA`.
- Gövde üç modda gelir: handshake öncesi düz, şifreli gelen (seçici + opcode),
  şifreli giden (seçici + sıra + opcode).
- Şifreleme: AES-CBC + PKCS#7, sabit IV. Anahtar seçici `1` oturum anahtarı,
  `2` gömülü sabit anahtar.
- Opcode çözülmüş düz metinde `plain[0]`'dır.
- 802.11 (DLT 105/127) desteklenir; şifreli gövdede LLC/SNAP okunamaz, gövde
  ham gösterilir.

## Uyarı

Bu araç yalnızca kendi bağlantınızı incelemek için kullanılmalıdır. Başkasının
trafiğini izlemek bulunduğunuz yerde suç olabilir.
