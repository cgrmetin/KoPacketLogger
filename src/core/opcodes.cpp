#include "core/opcodes.h"

#include <array>

namespace ko {
namespace {

// Opcode tablosu protokol notlarindan (protokol-notlari.md, bolum 6) alindi.
// Yon bilgisi PROVISIONAL: istemci kaynakli gorunen istekler Out, sunucu
// bildirimleri In olarak isaretlendi. IDA ajaninin ciktisi gelince dogrulanacak.
struct OpcodeEntry {
  std::uint8_t code;
  const char* name;
  Direction dir;
};

constexpr std::array<OpcodeEntry, 146> kOpcodes{ {
    { 0x01, "WIZ_LOGIN", Direction::Out },
    { 0x02, "WIZ_NEW_CHAR", Direction::Out },
    { 0x03, "WIZ_DEL_CHAR", Direction::Out },
    { 0x04, "WIZ_SEL_CHAR", Direction::Out },
    { 0x05, "WIZ_SEL_NATION", Direction::Out },
    { 0x06, "WIZ_MOVE", Direction::Out },
    { 0x07, "WIZ_USER_INOUT", Direction::In },
    { 0x08, "WIZ_ATTACK", Direction::Out },
    { 0x09, "WIZ_ROTATE", Direction::Out },
    { 0x0A, "WIZ_NPC_INOUT", Direction::In },
    { 0x0B, "WIZ_NPC_MOVE", Direction::In },
    { 0x0C, "WIZ_ALLCHAR_INFO_REQ", Direction::Out },
    { 0x0D, "WIZ_GAMESTART", Direction::Out },
    { 0x0E, "WIZ_MYINFO", Direction::In },
    { 0x0F, "WIZ_LOGOUT", Direction::Out },
    { 0x10, "WIZ_CHAT", Direction::Out },
    { 0x11, "WIZ_DEAD", Direction::In },
    { 0x12, "WIZ_REGENE", Direction::Out },
    { 0x13, "WIZ_TIME", Direction::In },
    { 0x14, "WIZ_WEATHER", Direction::In },
    { 0x15, "WIZ_REGIONCHANGE", Direction::In },
    { 0x16, "WIZ_REQ_USERIN", Direction::Out },
    { 0x17, "WIZ_HP_CHANGE", Direction::In },
    { 0x18, "WIZ_MSP_CHANGE", Direction::In },
    { 0x19, "WIZ_ITEM_LOG", Direction::In },
    { 0x1A, "WIZ_EXP_CHANGE", Direction::In },
    { 0x1B, "WIZ_LEVEL_CHANGE", Direction::In },
    { 0x1C, "WIZ_NPC_REGION", Direction::In },
    { 0x1D, "WIZ_REQ_NPCIN", Direction::Out },
    { 0x1E, "WIZ_WARP", Direction::In },
    { 0x1F, "WIZ_ITEM_MOVE", Direction::Out },
    { 0x20, "WIZ_NPC_EVENT", Direction::Out },
    { 0x21, "WIZ_ITEM_TRADE", Direction::Out },
    { 0x22, "WIZ_TARGET_HP", Direction::In },
    { 0x23, "WIZ_ITEM_DROP", Direction::Out },
    { 0x24, "WIZ_BUNDLE_OPEN_REQ", Direction::Out },
    { 0x25, "WIZ_TRADE_NPC", Direction::Out },
    { 0x26, "WIZ_ITEM_GET", Direction::Out },
    { 0x27, "WIZ_ZONE_CHANGE", Direction::In },
    { 0x28, "WIZ_POINT_CHANGE", Direction::In },
    { 0x29, "WIZ_STATE_CHANGE", Direction::In },
    { 0x2A, "WIZ_LOYALTY_CHANGE", Direction::In },
    { 0x2B, "WIZ_VERSION_CHECK", Direction::Out },
    { 0x2C, "WIZ_CRYPTION", Direction::Out },
    { 0x2D, "WIZ_USERLOOK_CHANGE", Direction::In },
    { 0x2E, "WIZ_NOTICE", Direction::In },
    { 0x2F, "WIZ_PARTY", Direction::In },
    { 0x30, "WIZ_EXCHANGE", Direction::Out },
    { 0x31, "WIZ_MAGIC_PROCESS", Direction::Out },
    { 0x32, "WIZ_SKILLPT_CHANGE", Direction::In },
    { 0x33, "WIZ_OBJECT_EVENT", Direction::Out },
    { 0x34, "WIZ_CLASS_CHANGE", Direction::Out },
    { 0x35, "WIZ_CHAT_TARGET", Direction::Out },
    { 0x36, "WIZ_CONCURRENTUSER", Direction::In },
    { 0x37, "WIZ_DATASAVE", Direction::Out },
    { 0x38, "WIZ_DURATION", Direction::In },
    { 0x39, "WIZ_TIMENOTIFY", Direction::In },
    { 0x3A, "WIZ_REPAIR_NPC", Direction::Out },
    { 0x3B, "WIZ_ITEM_REPAIR", Direction::Out },
    { 0x3C, "WIZ_KNIGHTS_PROCESS", Direction::Out },
    { 0x3D, "WIZ_ITEM_COUNT_CHANGE", Direction::In },
    { 0x3E, "WIZ_KNIGHTS_LIST", Direction::In },
    { 0x3F, "WIZ_ITEM_REMOVE", Direction::In },
    { 0x40, "WIZ_OPERATOR", Direction::In },
    { 0x41, "WIZ_SPEEDHACK_CHECK", Direction::In },
    { 0x42, "WIZ_COMPRESS_PACKET", Direction::In },
    { 0x43, "WIZ_SERVER_CHECK", Direction::In },
    { 0x44, "WIZ_CONTINOUS_PACKET", Direction::In },
    { 0x45, "WIZ_WAREHOUSE", Direction::Out },
    { 0x46, "WIZ_SERVER_CHANGE", Direction::In },
    { 0x47, "WIZ_REPORT_BUG", Direction::Out },
    { 0x48, "WIZ_HOME", Direction::Out },
    { 0x49, "WIZ_FRIEND_PROCESS", Direction::Out },
    { 0x4A, "WIZ_GOLD_CHANGE", Direction::In },
    { 0x4B, "WIZ_WARP_LIST", Direction::In },
    { 0x4C, "WIZ_VIRTUAL_SERVER", Direction::In },
    { 0x4D, "WIZ_ZONE_CONCURRENT", Direction::In },
    { 0x4E, "WIZ_CORPSE", Direction::In },
    { 0x4F, "WIZ_PARTY_BBS", Direction::Out },
    { 0x50, "WIZ_MARKET_BBS", Direction::Out },
    { 0x51, "WIZ_KICKOUT", Direction::In },
    { 0x52, "WIZ_CLIENT_EVENT", Direction::Out },
    { 0x53, "WIZ_MAP_EVENT", Direction::In },
    { 0x54, "WIZ_WEIGHT_CHANGE", Direction::In },
    { 0x55, "WIZ_SELECT_MSG", Direction::Out },
    { 0x56, "WIZ_NPC_SAY", Direction::In },
    { 0x57, "WIZ_BATTLE_EVENT", Direction::In },
    { 0x58, "WIZ_AUTHORITY_CHANGE", Direction::In },
    { 0x59, "WIZ_EDIT_BOX", Direction::In },
    { 0x5A, "WIZ_SANTA", Direction::In },
    { 0x5B, "WIZ_ITEM_UPGRADE", Direction::Out },
    { 0x5C, "WIZ_PACKET1", Direction::In },
    { 0x5D, "WIZ_PACKET2", Direction::In },
    { 0x5E, "WIZ_ZONEABILITY", Direction::In },
    { 0x5F, "WIZ_EVENT", Direction::In },
    { 0x60, "WIZ_STEALTH", Direction::In },
    { 0x61, "WIZ_ROOM_PACKETPROCESS", Direction::In },
    { 0x62, "WIZ_ROOM", Direction::Out },
    { 0x63, "WIZ_PACKET3", Direction::In },
    { 0x64, "WIZ_QUEST", Direction::Out },
    { 0x65, "WIZ_PACKET4", Direction::In },
    { 0x66, "WIZ_KISS", Direction::In },
    { 0x67, "WIZ_RECOMMEND_USER", Direction::In },
    { 0x68, "WIZ_MERCHANT", Direction::Out },
    { 0x69, "WIZ_MERCHANT_INOUT", Direction::In },
    { 0x6A, "WIZ_SHOPPING_MALL", Direction::Out },
    { 0x6B, "WIZ_SERVER_INDEX", Direction::In },
    { 0x6C, "WIZ_EFFECT", Direction::In },
    { 0x6D, "WIZ_SIEGE", Direction::In },
    { 0x6E, "WIZ_NAME_CHANGE", Direction::In },
    { 0x6F, "WIZ_WEBPAGE", Direction::In },
    { 0x70, "WIZ_CAPE", Direction::Out },
    { 0x71, "WIZ_PREMIUM", Direction::Out },
    { 0x72, "WIZ_HACKTOOL", Direction::In },
    { 0x73, "WIZ_RENTAL", Direction::In },
    { 0x74, "WIZ_PACKET5", Direction::In },
    { 0x75, "WIZ_CHALLENGE", Direction::Out },
    { 0x76, "WIZ_PET", Direction::Out },
    { 0x77, "WIZ_CHINA", Direction::In },
    { 0x78, "WIZ_KING", Direction::In },
    { 0x79, "WIZ_SKILLDATA", Direction::Out },
    { 0x7A, "WIZ_PROGRAMCHECK", Direction::Out },
    { 0x7B, "WIZ_BIFROST", Direction::In },
    { 0x7C, "WIZ_REPORT", Direction::Out },
    { 0x7D, "WIZ_LOGOSSHOUT", Direction::Out },
    { 0x7E, "WIZ_PACKET6", Direction::In },
    { 0x7F, "WIZ_PACKET7", Direction::In },
    { 0x80, "WIZ_RANK", Direction::In },
    { 0x81, "WIZ_STORY", Direction::In },
    { 0x82, "WIZ_PACKET8", Direction::In },
    { 0x83, "WIZ_PACKET9", Direction::In },
    { 0x84, "WIZ_PACKET10", Direction::In },
    { 0x85, "WIZ_PACKET11", Direction::In },
    { 0x86, "WIZ_MINING", Direction::Out },
    { 0x87, "WIZ_HELMET", Direction::In },
    { 0x88, "WIZ_PVP", Direction::Out },
    { 0x89, "WIZ_CHANGE_HAIR", Direction::Out },
    { 0x8A, "WIZ_PACKET12", Direction::In },
    { 0x8B, "WIZ_PACKET13", Direction::In },
    { 0x8C, "WIZ_PACKET14", Direction::In },
    { 0x8D, "WIZ_PACKET15", Direction::In },
    { 0x8E, "WIZ_PACKET16", Direction::In },
    { 0x8F, "WIZ_PACKET17", Direction::In },
    { 0x90, "WIZ_DEATH_LIST", Direction::In },
    { 0x91, "WIZ_CLANPOINTS_BATTLE", Direction::In },
    { 0xA0, "_____XINCODE_____", Direction::In },
} };

// Tablo opcode'a gore artan sirali oldugu icin ikili arama yeterli.
const OpcodeEntry* find(std::uint8_t opcode) {
  auto it = std::lower_bound(
      kOpcodes.begin(), kOpcodes.end(), opcode,
      [](const OpcodeEntry& e, std::uint8_t v) { return e.code < v; });
  if (it == kOpcodes.end() || it->code != opcode) return nullptr;
  return &*it;
}

} // namespace

const char* opcodeName(std::uint8_t opcode) {
  const OpcodeEntry* e = find(opcode);
  return e ? e->name : "UNKNOWN";
}

bool isKnownOpcode(std::uint8_t opcode) { return find(opcode) != nullptr; }

Direction opcodeDirection(std::uint8_t opcode) {
  const OpcodeEntry* e = find(opcode);
  return e ? e->dir : Direction::In;
}

} // namespace ko
