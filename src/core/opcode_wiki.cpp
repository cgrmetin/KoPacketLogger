#include "core/opcode_wiki.h"

#include <cstdio>
#include <string>

#include "core/opcodes.h"
#include "core/types.h"

namespace ko {
namespace {

// Alan tipinin bayt cinsinden genisligi. `Str` degisken uzunluktadir: 0 doner.
std::size_t fieldWidth(FieldType type) {
  switch (type) {
    case FieldType::U8:
      return 1;
    case FieldType::U16:
    case FieldType::Coord:
      return 2;
    case FieldType::U32:
    case FieldType::F32:
      return 4;
    case FieldType::U64:
      return 8;
    case FieldType::Str:
      return 0;
  }
  return 0;
}

const char* typeName(FieldType type) {
  switch (type) {
    case FieldType::U8:
      return "u8";
    case FieldType::U16:
      return "u16";
    case FieldType::U32:
      return "u32";
    case FieldType::U64:
      return "u64";
    case FieldType::F32:
      return "f32";
    case FieldType::Coord:
      return "coord (u16 / 10.0)";
    case FieldType::Str:
      return "str (uzunluk onekli)";
  }
  return "?";
}

void appendDirectionSection(std::string& out, Direction dir) {
  const char* const title = dir == Direction::In ? "Gelen (istemciye)" : "Giden (istemciden)";

  int documented = 0;
  for (int code = 0; code <= 0xFF; ++code) {
    const OpcodeInfo* info = findOpcode(static_cast<std::uint8_t>(code), dir);
    if (info == nullptr || info->dir != dir) continue;
    ++documented;
  }

  char header[256];
  std::snprintf(header, sizeof(header), "\n## %s — %d opcode\n\n", title, documented);
  out += header;

  if (documented == 0) {
    out += "_Bu yonde kayitli opcode yok._\n";
    return;
  }

  for (int code = 0; code <= 0xFF; ++code) {
    const OpcodeInfo* info = findOpcode(static_cast<std::uint8_t>(code), dir);
    if (info == nullptr || info->dir != dir) continue;

    char line[512];
    std::snprintf(line, sizeof(line), "\n### `0x%02X` %s\n\n", code, info->name);
    out += line;

    if (info->provisional) out += "> Alan adlari canli trafikle dogrulanmadi.\n\n";
    if (info->variant) out += "> Offset 1 alt secici (varyant) baytidir; govde ona gore degisir.\n\n";

    out += "| Offset | Tip | Ad | Not |\n|---|---|---|---|\n";
    out += "| 0 | u8 | opcode | paket turu |\n";

    std::size_t cursor = 1;
    for (std::uint8_t i = 0; i < info->fieldCount; ++i) {
      const FieldSpec& field = info->fields[i];
      const std::size_t width = fieldWidth(field.type);

      // Alanlar artan offsette beklenir; tabloda bosluk varsa gorunur kalsin.
      const char* gap = field.offset > cursor ? "onceki alandan bosluk" : "";
      char row[256];
      std::snprintf(row, sizeof(row), "| %u | %s | %s | %s |\n", static_cast<unsigned>(field.offset),
                    typeName(field.type), field.name, gap);
      out += row;

      if (width > 0) cursor = static_cast<std::size_t>(field.offset) + width;
    }

    if (info->fieldCount == 0) {
      out += "\n_Govdesi okunmuyor (alan tanimi yok)._\n";
    }
  }
}

}  // namespace

std::string buildOpcodeWiki() {
  std::string out;
  out += "# KoPacketLogger — protokol wikisi\n\n";
  out += "Opcode tablosundan uretilir; canli yakalama gerektirmez.\n\n";
  out += "## Cerceve\n\n";
  out += "```\nAA 55 | uint16 LE govde_uzunlugu | govde | 55 AA\n```\n\n";
  out += "Toplam `len + 6`. Parser en az 7 bayt ister. Magic veya kuyruk uyusmazsa\n";
  out += "2 bayt sola kaydirilip resync yapilir. Yon basina ayri tampon tutulur.\n\n";
  out += "## Govde modlari\n\n";
  out += "1. Sifresiz (handshake oncesi): `[opcode][alanlar]`\n";
  out += "2. Sifreli gelen: `[secici][opcode][alanlar]`\n";
  out += "3. Sifreli giden: `[secici][sira][opcode][alanlar]`\n\n";
  out += "Secici `1` oturum anahtari, `2` gomulu sabit anahtardir. Sira 1..250,\n";
  out += "`0xFA` ustunde 1'e sarar. AES-CBC + PKCS#7, IV sabit.\n\n";
  out += "Cozulmus duz metinde opcode **her iki yonde de** `plain[0]`'dir.\n";
  out += "Asagidaki offsetler duz metne gore verilmistir.\n";

  appendDirectionSection(out, Direction::In);
  appendDirectionSection(out, Direction::Out);
  return out;
}

std::string buildLayoutTable(const DecodedPacket& payload) {
  std::string out;
  const OpcodeInfo* info = findOpcode(payload.opcode, payload.raw.dir);
  if (info == nullptr) {
    char line[128];
    std::snprintf(line, sizeof(line), "0x%02X icin alan tanimi yok.", payload.opcode);
    return line;
  }

  char header[256];
  std::snprintf(header, sizeof(header), "%s (0x%02X)", info->name, info->opcode);
  out = header;
  if (info->provisional) out += "  [dogrulanmadi]";
  out += "\n\n";
  out += "| Offset | Tip | Ad |\n|---|---|---|\n";
  out += "| 0 | u8 | opcode |\n";

  for (std::uint8_t i = 0; i < info->fieldCount; ++i) {
    const FieldSpec& field = info->fields[i];
    char row[256];
    std::snprintf(row, sizeof(row), "| %u | %s | %s |\n", static_cast<unsigned>(field.offset),
                  typeName(field.type), field.name);
    out += row;
  }

  if (info->fieldCount == 0) out += "\n_Govdesi okunmuyor._\n";
  return out;
}

}  // namespace ko
