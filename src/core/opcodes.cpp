#include "core/opcodes.h"

namespace ko {
namespace {

// ===========================================================================
// Opcode tablosu - IDA verisinden (dump-analiz.md bolum 5) uretildi.
//
// Kaynak: pkt_dispatch_base (0x854A40) switch'i. Tablodaki her satir bir
// handler'dan cikarildi; alanlar (offset/tip) handler'in gövde okuma sirasidir.
// Offset 0 opcode'un kendisidir, bu yuzden alanlar 1'den baslar.
//
// Yon: pkt_dispatch_base yalnizca ALIM yolundan cagrilir
// (pkt_parse_frames -> pkt_dispatch_main -> pkt_dispatch_base), bu yuzden
// tum kayitlar Direction::In'dir. Giden opcode'lar icin IDA'da ayri bir
// merkezi dagitici bulunamadi (pkt_send_wrap'i 541 farkli fonksiyon cagiriyor);
// bu yuzden Out tablosu bos birakildi ve findOpcode In'e geri duser.
//
// Alan adlari: yalnizca decompile ile anlami cikarilabilen alanlara ad verildi
// (kaynak: dword_11299C0 / dword_1129A7C uzerindeki atama hedefi, log metni,
// /10.0 bolmesi). Anlami cikarilamayanlara f1, f2, ... notr adi verildi.
//
// ---------------------------------------------------------------------------
// DOGRULANMAYAN NOKTALAR (dump-analiz.md bolum 6'dan; kod hala bunlara dayaniyor)
//   1. dword_112A878'i (ek 8 baytlik baslik modu) 1 yapan kod yolu bulunamadi;
//      sub_8E3380 yalnizca 0 yaziyor.
//   2. Opcode'un kablo uzerinde 2. bayt olmasi KOSULLU: yalnizca sifreleme acik,
//      byte_1129B34 != 0 ve word_112614C alt bayti == 0 iken govde 1 bayt kayar.
//   3. Govde okumayan handler'lar (0x0D, 0x1E, 0x3B, 0x42, 0x5D, 0x6B, 0xB4, 0x7B,
//      0x01 sub_571530) icin islev cikarilmadi; fields = nullptr birakildi.
//   4. "string/skip sonrasi kesildi" isaretli kayitlarda alan listesi EKSIK:
//      fieldsTruncated = true. Ilk string veya 1700/1696 gibi buyuk atlamadan
//      sonraki alanlar tabloda yok.
//   5. Handler'larin semantik adlari buyuk olcude dogrulanmadi; yalnizca
//      handler icinde dogrudan kanit bulunan 18 opcode provisional = false.
//      Digerleri legacy Global.cs adini "_UNVERIFIED" sonekiyle tasiyor.
//   6. 0x0E (WIZ_MYINFO) alan sirasi cikarildi ama 1700+ offsetli item slotlari
//      cozulmedi.
//   7. Anahtarin hex degil ham bayt oldugu DOGRULANDI (sub_5EFAB0 dogrudan kopya).
//   8. pkt_dispatch_base'in vtable+8 uzerinden cagrildigi kismen dogrulandi:
//      0x70c221'deki call eax goruldu, vtable slot eslesmesi ispatlanamadi.
//   9. Giden sira numarasi araligi DOGRULANDI: 1..250 (0xFA), 0 hic kullanilmaz.
// ---------------------------------------------------------------------------
// ===========================================================================

constexpr FieldSpec kF_01[] = {
    { 1, FieldType::U8, "chat_type" },
    { 2, FieldType::U8, "channel" },
    { 3, FieldType::U16, "target_id" },
    { 5, FieldType::U8, "color" },
};
constexpr FieldSpec kF_02[] = {
    { 1, FieldType::U16, "kind" },
    { 2, FieldType::U16, "nation" },
    { 4, FieldType::U16, "x" },
    { 6, FieldType::U16, "z" },
    { 7, FieldType::U8, "kind" },
    { 8, FieldType::U16, "nation" },
    { 112, FieldType::U16, "x" },
    { 116, FieldType::U16, "z" },
    { 120, FieldType::U16, "field_120" },
};
constexpr FieldSpec kF_03[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U32, "char_id" },
    { 6, FieldType::U8, "nation" },
    { 7, FieldType::U8, "class" },
    { 8, FieldType::U16, "level" },
    { 10, FieldType::U16, "hp" },
    { 12, FieldType::U16, "x" },
    { 14, FieldType::U16, "z" },
    { 16, FieldType::U16, "region" },
    { 18, FieldType::U16, "zone" },
    { 118, FieldType::U8, "sub_type" },
    { 1818, FieldType::U8, "field_1818" },
    { 1820, FieldType::U16, "field_1820" },
    { 1822, FieldType::U8, "field_1822" },
    { 1857, FieldType::U8, "field_1857" },
};
constexpr FieldSpec kF_04[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U16, "name_len" },
    { 4, FieldType::Str, "name" },
    { 5, FieldType::U8, "event_type" },
    { 7, FieldType::U16, "sub_arg1" },
    { 9, FieldType::U8, "sub_arg2" },
    { 11, FieldType::Str, "text" },
    { 12, FieldType::U8, "sub_arg3" },
    { 47, FieldType::U8, "index" },
    { 48, FieldType::Str, "separator" },
    { 49, FieldType::U8, "sub_index" },
    { 51, FieldType::U16, "value_1" },
    { 53, FieldType::U16, "value_2" },
    { 55, FieldType::U16, "value_3" },
    { 57, FieldType::U16, "value_4" },
    { 161, FieldType::U8, "field_161" },
    { 1861, FieldType::U8, "field_1861" },
    { 1863, FieldType::U16, "field_1863" },
    { 1865, FieldType::U8, "field_1865" },
    { 1900, FieldType::U8, "field_1900" },
};
constexpr FieldSpec kF_05[] = {
    { 1, FieldType::U8, "obj_id" },
    { 2, FieldType::U16, "code" },
    { 4, FieldType::Str, "text" },
    { 34, FieldType::U8, "field_34" },
    { 36, FieldType::U16, "field_36" },
    { 38, FieldType::U8, "field_38" },
    { 40, FieldType::Str, "field_40" },
    { 41, FieldType::U8, "field_41" },
    { 76, FieldType::U8, "field_76" },
    { 77, FieldType::Str, "field_77" },
    { 78, FieldType::U8, "field_78" },
    { 80, FieldType::U16, "field_80" },
    { 82, FieldType::U16, "field_82" },
    { 84, FieldType::U16, "field_84" },
    { 86, FieldType::U16, "field_86" },
    { 190, FieldType::U8, "field_190" },
    { 1890, FieldType::U8, "field_1890" },
    { 1892, FieldType::U16, "field_1892" },
};
constexpr FieldSpec kF_06[] = {
    { 1, FieldType::U32, "obj_id" },
    { 5, FieldType::Coord, "item_id" },
    { 7, FieldType::Coord, "count" },
    { 9, FieldType::Coord, "item_value" },
    { 11, FieldType::Coord, "item_status" },
    { 13, FieldType::U8, "dir" },
};
constexpr FieldSpec kF_07[] = {
    { 1, FieldType::U8, "nation" },
    { 2, FieldType::U8, "x" },
    { 106, FieldType::U16, "equip_item_1" },
    { 108, FieldType::U16, "equip_item_2" },
    { 110, FieldType::U16, "equip_item_3" },
    { 112, FieldType::U16, "equip_item_4" },
    { 114, FieldType::U16, "equip_item_5" },
    { 116, FieldType::U16, "equip_item_6" },
    { 118, FieldType::U16, "equip_item_7" },
    { 119, FieldType::U16, "equip_item_8" },
    { 123, FieldType::U16, "equip_item_9" },
    { 128, FieldType::U16, "equip_item_10" },
    { 137, FieldType::U16, "equip_item_11" },
    { 139, FieldType::U16, "equip_item_12" },
    { 141, FieldType::U16, "equip_item_13" },
    { 143, FieldType::U16, "equip_item_14" },
    { 145, FieldType::U16, "equip_item_15" },
    { 147, FieldType::U8, "equip_item_16" },
    { 152, FieldType::Str, "name" },
    { 153, FieldType::U8, "name_len" },
    { 157, FieldType::Str, "guild_name" },
    { 158, FieldType::U16, "field_158" },
    { 160, FieldType::U16, "field_160" },
};
constexpr FieldSpec kF_08[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U32, "char_id" },
    { 7, FieldType::U32, "target_id" },
};
constexpr FieldSpec kF_09[] = {
    { 1, FieldType::U8, "char_id" },
    { 2, FieldType::U16, "sub_type" },
    { 3, FieldType::U16, "obj_id" },
    { 4, FieldType::U16, "char_id" },
    { 5, FieldType::U8, "angle" },
    { 7, FieldType::U16, "angle" },
    { 9, FieldType::U16, "field_9" },
    { 11, FieldType::U16, "field_11" },
    { 13, FieldType::U16, "field_13" },
    { 15, FieldType::U8, "field_15" },
    { 20, FieldType::Str, "field_20" },
    { 21, FieldType::U8, "field_21" },
    { 25, FieldType::Str, "field_25" },
    { 26, FieldType::U16, "field_26" },
    { 28, FieldType::U16, "field_28" },
    { 30, FieldType::Str, "field_30" },
    { 31, FieldType::Str, "field_31" },
    { 32, FieldType::Str, "field_32" },
    { 33, FieldType::Str, "field_33" },
    { 34, FieldType::Str, "field_34" },
    { 35, FieldType::Str, "field_35" },
    { 36, FieldType::Str, "field_36" },
    { 37, FieldType::Str, "field_37" },
    { 38, FieldType::Str, "field_38" },
    { 39, FieldType::Str, "field_39" },
    { 40, FieldType::Str, "field_40" },
    { 41, FieldType::Str, "field_41" },
    { 42, FieldType::Str, "field_42" },
    { 43, FieldType::Str, "field_43" },
    { 44, FieldType::Str, "field_44" },
    { 45, FieldType::Str, "field_45" },
    { 46, FieldType::Str, "field_46" },
    { 47, FieldType::Str, "field_47" },
    { 48, FieldType::Str, "field_48" },
    { 49, FieldType::Str, "field_49" },
    { 50, FieldType::Str, "field_50" },
    { 51, FieldType::Str, "field_51" },
    { 52, FieldType::Str, "field_52" },
    { 53, FieldType::Str, "field_53" },
    { 54, FieldType::Str, "field_54" },
    { 55, FieldType::Str, "field_55" },
    { 56, FieldType::Str, "field_56" },
};
constexpr FieldSpec kF_0A[] = {
    { 1, FieldType::U32, "obj_id" },
    { 5, FieldType::U16, "kind" },
    { 7, FieldType::U8, "obj_type" },
    { 8, FieldType::U16, "network_id" },
    { 10, FieldType::U32, "field_10" },
    { 14, FieldType::U8, "npc_type" },
    { 15, FieldType::U32, "field_15" },
    { 19, FieldType::U16, "field_19" },
    { 21, FieldType::U32, "x" },
    { 25, FieldType::U32, "z" },
    { 29, FieldType::U8, "y" },
    { 30, FieldType::Str, "name" },
    { 43, FieldType::U16, "time" },
};
constexpr FieldSpec kF_0B[] = {
    { 1, FieldType::U8, "obj_id" },
    { 2, FieldType::U32, "obj_id_hi" },
    { 6, FieldType::Coord, "x" },
    { 8, FieldType::Coord, "y" },
    { 10, FieldType::Coord, "z" },
    { 12, FieldType::Coord, "dir" },
};
constexpr FieldSpec kF_0C[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_0E[] = {
    { 1, FieldType::U32, "char_id" },
    { 5, FieldType::U8, "name_len" },
    { 6, FieldType::Str, "name" },
    { 7, FieldType::U16, "x" },
    { 9, FieldType::U8, "y" },
    { 11, FieldType::U8, "z" },
    { 31, FieldType::U8, "class" },
    { 33, FieldType::U16, "field_33" },
    { 37, FieldType::U8, "field_37" },
    { 38, FieldType::U8, "field_38" },
    { 42, FieldType::U16, "field_42" },
    { 44, FieldType::U16, "color" },
    { 46, FieldType::U16, "field_46" },
    { 48, FieldType::U8, "field_48" },
    { 52, FieldType::U8, "field_52" },
    { 54, FieldType::U16, "field_54" },
    { 56, FieldType::U8, "field_56" },
    { 60, FieldType::U8, "field_60" },
    { 84, FieldType::U16, "field_84" },
    { 108, FieldType::U8, "field_108" },
    { 128, FieldType::U8, "field_128" },
    { 129, FieldType::U16, "field_129" },
};
constexpr FieldSpec kF_10[] = {
    { 1, FieldType::U8, "chat_type" },
    { 2, FieldType::U64, "nation" },
    { 10, FieldType::U64, "message_len" },
    { 18, FieldType::U8, "color" },
    { 19, FieldType::U16, "color2" },
    { 21, FieldType::U16, "swap_flag" },
    { 23, FieldType::U16, "swap_flag" },
    { 25, FieldType::U16, "name" },
    { 27, FieldType::U16, "name" },
    { 29, FieldType::U16, "guild_name" },
    { 31, FieldType::U8, "type" },
    { 32, FieldType::U8, "sub_type" },
    { 33, FieldType::U8, "name_len" },
    { 34, FieldType::U8, "count" },
    { 35, FieldType::Str, "field_35" },
    { 36, FieldType::Str, "field_36" },
    { 37, FieldType::Str, "field_37" },
    { 38, FieldType::Str, "field_38" },
    { 39, FieldType::Str, "field_39" },
    { 40, FieldType::Str, "field_40" },
    { 41, FieldType::Str, "field_41" },
    { 42, FieldType::Str, "field_42" },
    { 43, FieldType::Str, "field_43" },
    { 44, FieldType::Str, "field_44" },
    { 45, FieldType::Str, "field_45" },
    { 46, FieldType::Str, "field_46" },
    { 47, FieldType::Str, "field_47" },
    { 48, FieldType::Str, "field_48" },
    { 49, FieldType::Str, "field_49" },
    { 50, FieldType::Str, "field_50" },
    { 51, FieldType::Str, "field_51" },
    { 52, FieldType::Str, "field_52" },
    { 53, FieldType::Str, "field_53" },
    { 54, FieldType::Str, "field_54" },
    { 55, FieldType::U16, "text_len" },
    { 59, FieldType::Str, "field_59" },
    { 60, FieldType::Str, "field_60" },
    { 61, FieldType::Str, "field_61" },
    { 62, FieldType::Str, "field_62" },
};
constexpr FieldSpec kF_11[] = {
    { 1, FieldType::U32, "char_id" },
    { 5, FieldType::U32, "killer_id" },
    { 36, FieldType::U8, "field_36" },
    { 132, FieldType::U8, "field_132" },
    { 167, FieldType::U16, "field_167" },
};
constexpr FieldSpec kF_12[] = {
    { 1, FieldType::U16, "sub_type" },
    { 3, FieldType::U16, "z" },
    { 5, FieldType::U16, "type" },
    { 6, FieldType::U16, "char_id" },
    { 11, FieldType::U16, "obj_id" },
    { 20, FieldType::U16, "uid" },
    { 22, FieldType::U16, "field_22" },
    { 24, FieldType::U16, "field_24" },
    { 25, FieldType::U16, "field_25" },
    { 27, FieldType::U16, "type" },
    { 29, FieldType::U16, "time" },
    { 31, FieldType::U8, "field_31" },
    { 36, FieldType::Str, "field_36" },
    { 37, FieldType::U8, "field_37" },
    { 41, FieldType::Str, "field_41" },
    { 42, FieldType::U16, "field_42" },
    { 44, FieldType::U16, "field_44" },
    { 46, FieldType::Str, "field_46" },
    { 47, FieldType::Str, "field_47" },
};
constexpr FieldSpec kF_14[] = {
    { 1, FieldType::U8, "sound_type" },
    { 2, FieldType::U16, "volume" },
};
constexpr FieldSpec kF_15[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "count" },
    { 4, FieldType::U32, "obj_id" },
    { 71, FieldType::U8, "field_71" },
    { 75, FieldType::Str, "field_75" },
    { 76, FieldType::U8, "field_76" },
    { 144, FieldType::U8, "field_144" },
    { 146, FieldType::U16, "field_146" },
    { 148, FieldType::U8, "field_148" },
    { 150, FieldType::U8, "field_150" },
    { 151, FieldType::U8, "field_151" },
    { 153, FieldType::U16, "field_153" },
    { 155, FieldType::U8, "field_155" },
    { 159, FieldType::U8, "field_159" },
    { 161, FieldType::U16, "field_161" },
    { 163, FieldType::U16, "field_163" },
    { 165, FieldType::U16, "field_165" },
    { 167, FieldType::U8, "field_167" },
    { 171, FieldType::U8, "field_171" },
    { 175, FieldType::U8, "field_175" },
    { 177, FieldType::U8, "field_177" },
    { 179, FieldType::U16, "field_179" },
    { 181, FieldType::U16, "field_181" },
    { 183, FieldType::U8, "field_183" },
    { 187, FieldType::U8, "field_187" },
    { 191, FieldType::U8, "field_191" },
    { 193, FieldType::U8, "field_193" },
    { 197, FieldType::U8, "field_197" },
    { 202, FieldType::U8, "field_202" },
};
constexpr FieldSpec kF_16[] = {
    { 1, FieldType::U16, "count" },
};
constexpr FieldSpec kF_17[] = {
    { 1, FieldType::U16, "hp" },
    { 3, FieldType::U16, "hp_max" },
    { 5, FieldType::U32, "char_id" },
    { 39, FieldType::U8, "field_39" },
    { 43, FieldType::U16, "field_43" },
    { 45, FieldType::U8, "field_45" },
    { 597, FieldType::U16, "field_597" },
    { 599, FieldType::U8, "field_599" },
};
constexpr FieldSpec kF_18[] = {
    { 1, FieldType::U16, "msp_max" },
    { 3, FieldType::U16, "msp" },
    { 4, FieldType::U16, "msp" },
    { 37, FieldType::U8, "field_37" },
    { 41, FieldType::U16, "field_41" },
    { 43, FieldType::U8, "field_43" },
    { 595, FieldType::U16, "field_595" },
};
constexpr FieldSpec kF_19[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_1A[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U64, "amount" },
    { 10, FieldType::U32, "x" },
    { 14, FieldType::U16, "z" },
};
constexpr FieldSpec kF_1B[] = {
    { 1, FieldType::U32, "char_id" },
    { 5, FieldType::U8, "nation" },
    { 6, FieldType::U8, "char_id" },
    { 7, FieldType::U16, "nation" },
    { 9, FieldType::U8, "nation" },
    { 10, FieldType::U64, "x" },
    { 18, FieldType::U16, "z" },
    { 20, FieldType::U16, "hp" },
    { 22, FieldType::U16, "hp_max" },
    { 24, FieldType::U16, "mp" },
    { 26, FieldType::U32, "mp_max" },
    { 30, FieldType::U32, "x" },
    { 39, FieldType::U8, "z" },
};
constexpr FieldSpec kF_1C[] = {
    { 1, FieldType::U16, "count" },
    { 3, FieldType::U16, "obj_id" },
    { 5, FieldType::U8, "count" },
    { 9, FieldType::U16, "id_1" },
    { 11, FieldType::U16, "id_2" },
    { 13, FieldType::U8, "id_3" },
    { 15, FieldType::U16, "id_4" },
    { 17, FieldType::Str, "id_5" },
    { 18, FieldType::U8, "id_6" },
    { 20, FieldType::U8, "id_7" },
    { 40, FieldType::U16, "field_40" },
};
constexpr FieldSpec kF_1D[] = {
    { 1, FieldType::U16, "count" },
};
constexpr FieldSpec kF_1F[] = {
    { 1, FieldType::U8, "update_type" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U8, "hp" },
    { 4, FieldType::U8, "mp" },
    { 5, FieldType::U8, "field_5" },
    { 6, FieldType::U8, "field_6" },
    { 7, FieldType::U16, "hp" },
    { 9, FieldType::U8, "mp" },
};
constexpr FieldSpec kF_20[] = {
    { 1, FieldType::U8, "sound_type" },
    { 2, FieldType::U8, "volume" },
    { 3, FieldType::U16, "target_id" },
    { 7, FieldType::U8, "type" },
    { 9, FieldType::U16, "obj_id" },
    { 11, FieldType::U16, "target_id" },
    { 15, FieldType::Str, "sub_type" },
    { 16, FieldType::U8, "field_16" },
    { 20, FieldType::U16, "field_20" },
};
constexpr FieldSpec kF_21[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "sub_action" },
    { 3, FieldType::U32, "x" },
    { 7, FieldType::U32, "z" },
    { 11, FieldType::U8, "field_11" },
};
constexpr FieldSpec kF_22[] = {
    { 1, FieldType::U32, "count" },
    { 5, FieldType::U8, "flag" },
    { 6, FieldType::U32, "hp" },
    { 10, FieldType::U32, "hp" },
    { 14, FieldType::U8, "count" },
    { 115, FieldType::U8, "field_115" },
    { 119, FieldType::U8, "field_119" },
};
constexpr FieldSpec kF_23[] = {
    { 1, FieldType::U32, "char_id" },
    { 5, FieldType::U32, "obj_id" },
    { 9, FieldType::U8, "field_9" },
};
constexpr FieldSpec kF_24[] = {
    { 1, FieldType::U32, "value" },
    { 5, FieldType::U8, "type" },
    { 6, FieldType::U32, "obj_id" },
    { 10, FieldType::U16, "sub_type" },
};
constexpr FieldSpec kF_25[] = {
    { 1, FieldType::U32, "target_id" },
    { 36, FieldType::U16, "item_id" },
    { 38, FieldType::U16, "item_id" },
    { 40, FieldType::U16, "item_id" },
    { 144, FieldType::U8, "item_id" },
    { 148, FieldType::U8, "item_id" },
};
constexpr FieldSpec kF_26[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U32, "amount" },
    { 6, FieldType::U8, "item_id" },
    { 7, FieldType::Str, "name" },
    { 8, FieldType::Str, "message" },
    { 9, FieldType::U8, "name_len" },
    { 10, FieldType::U16, "name_len" },
    { 12, FieldType::U16, "name" },
};
constexpr FieldSpec kF_28[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U16, "hp" },
    { 4, FieldType::U16, "hp_max" },
    { 6, FieldType::U16, "mp" },
    { 8, FieldType::U16, "x" },
    { 10, FieldType::U32, "z" },
    { 14, FieldType::U8, "field_14" },
};
constexpr FieldSpec kF_29[] = {
    { 1, FieldType::U32, "char_id" },
    { 5, FieldType::U16, "type" },
    { 7, FieldType::U8, "action" },
};
constexpr FieldSpec kF_2A[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U32, "x" },
    { 6, FieldType::U32, "z" },
    { 10, FieldType::U32, "sub_type" },
    { 14, FieldType::U32, "x" },
};
constexpr FieldSpec kF_2D[] = {
    { 1, FieldType::U32, "char_id" },
    { 5, FieldType::U8, "sub_type" },
    { 6, FieldType::U32, "time_ms" },
    { 10, FieldType::U16, "durability" },
    { 12, FieldType::U8, "upgrade" },
    { 13, FieldType::U8, "look_type" },
    { 14, FieldType::Str, "look_1" },
    { 15, FieldType::Str, "look_2" },
    { 16, FieldType::Str, "look_3" },
    { 17, FieldType::Str, "look_4" },
    { 18, FieldType::Str, "look_5" },
    { 19, FieldType::Str, "look_6" },
    { 20, FieldType::Str, "look_7" },
    { 21, FieldType::U16, "look_8" },
    { 22, FieldType::Str, "look_9" },
    { 23, FieldType::Str, "look_10" },
    { 24, FieldType::U8, "look_11" },
};
constexpr FieldSpec kF_2E[] = {
    { 1, FieldType::U8, "notice_type" },
};
constexpr FieldSpec kF_2F[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::Str, "member_name" },
    { 3, FieldType::Str, "member_name" },
    { 4, FieldType::Str, "member_name" },
    { 5, FieldType::Str, "member_name" },
    { 6, FieldType::Str, "member_name" },
    { 7, FieldType::Str, "member_name" },
    { 8, FieldType::Str, "member_name" },
    { 9, FieldType::Str, "member_name" },
    { 10, FieldType::Str, "member_name" },
    { 11, FieldType::Str, "member_name" },
    { 12, FieldType::Str, "member_name" },
    { 13, FieldType::Str, "member_name" },
    { 14, FieldType::Str, "member_name" },
    { 15, FieldType::Str, "member_name" },
    { 16, FieldType::Str, "member_name" },
    { 17, FieldType::Str, "member_name" },
    { 18, FieldType::Str, "member_name" },
    { 19, FieldType::U8, "count" },
    { 54, FieldType::U16, "field_54" },
    { 56, FieldType::U16, "field_56" },
    { 58, FieldType::U8, "field_58" },
    { 93, FieldType::U8, "field_93" },
};
constexpr FieldSpec kF_30[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U32, "char_id" },
    { 6, FieldType::U8, "sub_type" },
    { 7, FieldType::U8, "open_flag" },
    { 8, FieldType::U32, "obj_id" },
    { 12, FieldType::U64, "target_obj_id" },
    { 20, FieldType::U32, "field_20" },
    { 24, FieldType::U8, "state" },
    { 25, FieldType::U8, "flag" },
    { 26, FieldType::U32, "field_26" },
    { 30, FieldType::U16, "item_id" },
    { 32, FieldType::U16, "field_32" },
    { 34, FieldType::U8, "field_34" },
    { 35, FieldType::U32, "obj_id" },
    { 39, FieldType::U8, "field_39" },
};
constexpr FieldSpec kF_31[] = {
    { 1, FieldType::U8, "update_type" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U8, "hp" },
    { 19, FieldType::U8, "field_19" },
    { 48, FieldType::Str, "field_48" },
    { 49, FieldType::Str, "field_49" },
};
constexpr FieldSpec kF_33[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U64, "flag" },
    { 10, FieldType::U64, "char_id" },
    { 18, FieldType::U8, "sub_flag" },
    { 19, FieldType::U32, "dir" },
    { 23, FieldType::U8, "flag" },
};
constexpr FieldSpec kF_34[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "sub_type" },
    { 3, FieldType::U32, "class_id" },
};
constexpr FieldSpec kF_35[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "target_id" },
    { 4, FieldType::U32, "type" },
    { 8, FieldType::U32, "result" },
    { 12, FieldType::U32, "field_12" },
    { 16, FieldType::Str, "text" },
};
constexpr FieldSpec kF_36[] = {
    { 1, FieldType::U16, "weight" },
};
constexpr FieldSpec kF_38[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "value" },
};
constexpr FieldSpec kF_3A[] = {
    { 1, FieldType::U32, "target_id" },
    { 2, FieldType::U16, "obj_id" },
    { 4, FieldType::U8, "field_4" },
    { 8, FieldType::U16, "field_8" },
    { 10, FieldType::U16, "field_10" },
    { 14, FieldType::Str, "field_14" },
    { 15, FieldType::U8, "field_15" },
    { 19, FieldType::U16, "field_19" },
};
constexpr FieldSpec kF_3D[] = {
    { 1, FieldType::U16, "count" },
    { 3, FieldType::U8, "type" },
    { 4, FieldType::U8, "count" },
    { 5, FieldType::U32, "time_ms" },
    { 9, FieldType::U32, "value" },
    { 13, FieldType::U8, "type" },
    { 14, FieldType::U16, "item_count" },
    { 16, FieldType::U32, "obj_id" },
    { 20, FieldType::U32, "target_obj_id" },
    { 555, FieldType::U16, "field_555" },
    { 557, FieldType::U8, "field_557" },
    { 561, FieldType::U16, "field_561" },
    { 569, FieldType::U16, "field_569" },
};
constexpr FieldSpec kF_3E[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "value" },
    { 4, FieldType::U16, "id" },
    { 6, FieldType::U16, "name_len" },
    { 8, FieldType::Str, "name" },
    { 9, FieldType::U16, "field_9" },
    { 11, FieldType::U16, "field_11" },
    { 13, FieldType::U16, "field_13" },
    { 44, FieldType::U16, "name_len" },
    { 46, FieldType::U8, "field_46" },
};
constexpr FieldSpec kF_3F[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "msg_type" },
};
constexpr FieldSpec kF_40[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U64, "hp" },
    { 10, FieldType::U64, "z" },
    { 18, FieldType::U16, "state" },
    { 20, FieldType::U16, "index" },
    { 22, FieldType::Str, "obj_id" },
    { 26, FieldType::U8, "name" },
    { 34, FieldType::U16, "hp_max" },
    { 36, FieldType::U16, "ac" },
    { 38, FieldType::U16, "damage" },
    { 40, FieldType::U8, "attack_delay" },
    { 45, FieldType::U16, "attack_type" },
};
constexpr FieldSpec kF_44[] = {
    { 1, FieldType::U16, "total_len" },
    { 3, FieldType::U64, "entry_len" },
    { 11, FieldType::U64, "field_11" },
    { 19, FieldType::U16, "field_19" },
    { 21, FieldType::U16, "field_21" },
};
constexpr FieldSpec kF_45[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "arg" },
    { 3, FieldType::U8, "sub_type" },
    { 4, FieldType::U8, "value" },
    { 5, FieldType::U8, "value" },
    { 6, FieldType::U8, "value" },
    { 7, FieldType::U8, "value" },
    { 8, FieldType::U8, "value" },
};
constexpr FieldSpec kF_46[] = {
    { 1, FieldType::Str, "field_1" },
    { 3, FieldType::Str, "field_3" },
};
constexpr FieldSpec kF_49[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "name_len" },
    { 4, FieldType::Str, "name" },
    { 35, FieldType::U16, "field_35" },
    { 147, FieldType::U16, "field_147" },
    { 149, FieldType::U16, "field_149" },
    { 151, FieldType::U16, "field_151" },
    { 186, FieldType::U16, "field_186" },
    { 188, FieldType::U16, "field_188" },
};
constexpr FieldSpec kF_4A[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U32, "amount" },
    { 6, FieldType::U32, "gold" },
    { 8, FieldType::U8, "char_id" },
    { 12, FieldType::U8, "char_id" },
};
constexpr FieldSpec kF_4B[] = {
    { 1, FieldType::U8, "kind" },
    { 2, FieldType::U16, "count" },
    { 4, FieldType::U16, "obj_id" },
    { 6, FieldType::U16, "name" },
    { 8, FieldType::Str, "name2" },
    { 10, FieldType::Str, "field_10" },
    { 11, FieldType::U16, "field_11" },
    { 13, FieldType::U8, "field_13" },
    { 461, FieldType::Str, "field_461" },
    { 462, FieldType::U8, "field_462" },
    { 2570, FieldType::U16, "field_2570" },
    { 2572, FieldType::U16, "field_2572" },
};
constexpr FieldSpec kF_4E[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U16, "count" },
    { 4, FieldType::U32, "time" },
    { 8, FieldType::U8, "field_8" },
    { 9, FieldType::U8, "count" },
    { 10, FieldType::Str, "time" },
    { 45, FieldType::Str, "field_45" },
    { 46, FieldType::U16, "field_46" },
    { 48, FieldType::U8, "field_48" },
    { 52, FieldType::U16, "field_52" },
    { 86, FieldType::Str, "field_86" },
    { 87, FieldType::Str, "field_87" },
    { 88, FieldType::Str, "field_88" },
    { 89, FieldType::U8, "field_89" },
    { 124, FieldType::Str, "field_124" },
    { 125, FieldType::Str, "field_125" },
    { 126, FieldType::Str, "field_126" },
    { 127, FieldType::Str, "field_127" },
    { 128, FieldType::Str, "field_128" },
    { 129, FieldType::Str, "field_129" },
    { 130, FieldType::U8, "field_130" },
    { 165, FieldType::Str, "field_165" },
    { 166, FieldType::Str, "field_166" },
};
constexpr FieldSpec kF_4F[] = {
    { 1, FieldType::U8, "state" },
};
constexpr FieldSpec kF_50[] = {
    { 1, FieldType::U8, "mode" },
    { 2, FieldType::U8, "side" },
    { 3, FieldType::U8, "flag" },
    { 4, FieldType::U8, "notice_id" },
    { 5, FieldType::U8, "notice_type" },
};
constexpr FieldSpec kF_53[] = {
    { 1, FieldType::U8, "action" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U32, "value" },
    { 7, FieldType::U16, "time" },
    { 9, FieldType::U8, "type" },
    { 10, FieldType::U8, "value" },
};
constexpr FieldSpec kF_54[] = {
    { 1, FieldType::U32, "weight" },
    { 5, FieldType::U8, "weight_delta" },
    { 6, FieldType::Str, "coord" },
    { 7, FieldType::Str, "field_7" },
    { 8, FieldType::Str, "field_8" },
    { 9, FieldType::Str, "field_9" },
    { 10, FieldType::Str, "field_10" },
    { 11, FieldType::Str, "field_11" },
    { 12, FieldType::Str, "field_12" },
    { 13, FieldType::Str, "field_13" },
    { 14, FieldType::U16, "field_14" },
    { 15, FieldType::Str, "field_15" },
    { 16, FieldType::Str, "field_16" },
    { 17, FieldType::U8, "field_17" },
    { 52, FieldType::U8, "field_52" },
    { 87, FieldType::U8, "field_87" },
    { 183, FieldType::U8, "field_183" },
};
constexpr FieldSpec kF_55[] = {
    { 1, FieldType::U32, "obj_id" },
    { 5, FieldType::U8, "kind" },
    { 6, FieldType::U32, "sub_type" },
    { 39, FieldType::Str, "field_39" },
};
constexpr FieldSpec kF_57[] = {
    { 1, FieldType::U8, "sub_opcode" },
};
constexpr FieldSpec kF_58[] = {
    { 1, FieldType::U8, "kind" },
    { 2, FieldType::U32, "char_id" },
    { 6, FieldType::U8, "authority" },
};
constexpr FieldSpec kF_59[] = {
    { 1, FieldType::U8, "sub_opcode" },
};
constexpr FieldSpec kF_5A[] = {
    { 1, FieldType::U8, "sub_opcode" },
};
constexpr FieldSpec kF_5B[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_5E[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "flag_a" },
    { 3, FieldType::U8, "mode" },
    { 4, FieldType::U8, "flag_b" },
    { 5, FieldType::U16, "value" },
    { 7, FieldType::U8, "flag_a" },
    { 8, FieldType::U8, "value" },
    { 9, FieldType::U8, "flag_b" },
    { 10, FieldType::U32, "option_value" },
};
constexpr FieldSpec kF_5F[] = {
    { 1, FieldType::U8, "kind" },
    { 2, FieldType::U8, "action" },
    { 3, FieldType::Str, "text" },
    { 4, FieldType::Str, "text" },
    { 5, FieldType::Str, "text" },
    { 6, FieldType::Str, "text" },
    { 7, FieldType::Str, "text" },
    { 8, FieldType::Str, "text" },
    { 9, FieldType::U8, "field_9" },
    { 10, FieldType::U8, "field_10" },
};
constexpr FieldSpec kF_60[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "duration" },
};
constexpr FieldSpec kF_61[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_63[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "target_id" },
    { 4, FieldType::U8, "success" },
};
constexpr FieldSpec kF_64[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "quest_state" },
    { 3, FieldType::U16, "quest_id" },
    { 5, FieldType::U16, "quest_level" },
    { 7, FieldType::U32, "npc_id" },
    { 11, FieldType::U32, "quest_time" },
    { 325, FieldType::Str, "title" },
    { 326, FieldType::Str, "name" },
    { 327, FieldType::U16, "action" },
    { 329, FieldType::Str, "desc" },
    { 330, FieldType::U16, "field_330" },
    { 366, FieldType::U16, "field_366" },
    { 402, FieldType::U16, "field_402" },
    { 438, FieldType::U8, "state" },
    { 442, FieldType::U16, "field_442" },
};
constexpr FieldSpec kF_65[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_66[] = {
    { 1, FieldType::U32, "src_id" },
    { 5, FieldType::U32, "dst_id" },
};
constexpr FieldSpec kF_68[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "state" },
};
constexpr FieldSpec kF_69[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U32, "char_id" },
    { 6, FieldType::U16, "count" },
    { 8, FieldType::U32, "stat_1" },
    { 12, FieldType::U32, "stat_2" },
    { 16, FieldType::U32, "stat_3" },
    { 20, FieldType::U32, "stat_4" },
    { 24, FieldType::U32, "stat_5" },
    { 28, FieldType::U32, "stat_6" },
    { 32, FieldType::U32, "stat_7" },
    { 36, FieldType::U32, "stat_8" },
    { 40, FieldType::U8, "sub_type" },
    { 41, FieldType::U16, "count" },
    { 43, FieldType::U32, "char_id" },
    { 47, FieldType::U8, "stat_index" },
    { 48, FieldType::U8, "flag" },
};
constexpr FieldSpec kF_6A[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_6C[] = {
    { 1, FieldType::U32, "obj_id" },
    { 5, FieldType::U16, "duration" },
    { 7, FieldType::U32, "duration" },
    { 11, FieldType::U8, "name_len" },
    { 12, FieldType::Str, "name" },
    { 102, FieldType::U16, "item_id" },
    { 104, FieldType::U16, "item_count" },
    { 106, FieldType::U8, "text_len" },
    { 141, FieldType::U8, "field_141" },
    { 142, FieldType::U8, "field_142" },
    { 144, FieldType::U8, "field_144" },
    { 148, FieldType::U16, "field_148" },
    { 152, FieldType::U16, "field_152" },
    { 154, FieldType::U8, "field_154" },
    { 158, FieldType::U8, "field_158" },
    { 262, FieldType::U8, "field_262" },
    { 366, FieldType::U8, "field_366" },
};
constexpr FieldSpec kF_6D[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "state" },
    { 3, FieldType::U8, "x" },
    { 5, FieldType::U16, "y" },
    { 7, FieldType::U8, "z" },
    { 8, FieldType::U8, "action" },
    { 12, FieldType::Str, "name_len" },
    { 13, FieldType::U16, "name" },
    { 109, FieldType::U16, "type" },
    { 111, FieldType::U16, "value" },
    { 113, FieldType::U8, "obj_id" },
    { 148, FieldType::U8, "type" },
    { 149, FieldType::U8, "value" },
    { 151, FieldType::U8, "obj_id" },
    { 155, FieldType::U16, "field_155" },
    { 159, FieldType::U16, "field_159" },
    { 161, FieldType::U8, "field_161" },
    { 165, FieldType::U8, "field_165" },
};
constexpr FieldSpec kF_6E[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "name_len" },
    { 290, FieldType::U8, "action" },
    { 291, FieldType::U8, "type" },
    { 293, FieldType::U16, "name_len" },
    { 295, FieldType::U8, "sub_type" },
    { 296, FieldType::U8, "sub_type2" },
    { 300, FieldType::Str, "name" },
    { 301, FieldType::U16, "name_len" },
    { 397, FieldType::U16, "action" },
    { 399, FieldType::U16, "type" },
    { 401, FieldType::U8, "sub_type" },
    { 436, FieldType::U8, "sub_type2" },
    { 437, FieldType::U8, "name_len" },
};
constexpr FieldSpec kF_70[] = {
    { 1, FieldType::U16, "sub_type" },
};
constexpr FieldSpec kF_71[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "count" },
    { 3, FieldType::U8, "slot" },
    { 4, FieldType::U16, "item_id" },
    { 6, FieldType::U8, "equipped_slot" },
    { 36, FieldType::U8, "premium_type" },
    { 37, FieldType::U8, "premium_value" },
    { 38, FieldType::U8, "field_38" },
};
constexpr FieldSpec kF_73[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "item_id" },
    { 4, FieldType::U8, "slot" },
};
constexpr FieldSpec kF_74[] = {
    { 1, FieldType::U32, "src_id" },
    { 5, FieldType::U16, "amount" },
    { 7, FieldType::U32, "dst_id" },
    { 11, FieldType::U16, "count" },
    { 37, FieldType::U16, "field_37" },
    { 38, FieldType::U8, "field_38" },
};
constexpr FieldSpec kF_75[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_76[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "mode" },
    { 3, FieldType::U32, "char_id" },
    { 7, FieldType::U32, "obj_id" },
    { 11, FieldType::U16, "index" },
    { 13, FieldType::U32, "type" },
    { 17, FieldType::U8, "flag" },
};
constexpr FieldSpec kF_78[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::Str, "name" },
    { 3, FieldType::U8, "sub_type" },
    { 38, FieldType::U16, "action" },
};
constexpr FieldSpec kF_79[] = {
    { 1, FieldType::U16, "state" },
    { 3, FieldType::U32, "skill_id" },
    { 37, FieldType::U16, "count" },
    { 72, FieldType::U16, "field_72" },
};
constexpr FieldSpec kF_3C[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "type" },
    { 4, FieldType::Str, "action" },
    { 5, FieldType::U16, "field_5" },
    { 6, FieldType::U8, "field_6" },
    { 41, FieldType::U16, "field_41" },
    { 43, FieldType::U8, "field_43" },
};
constexpr FieldSpec kF_7A[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_7C[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::Str, "text" },
    { 3, FieldType::Str, "message" },
    { 4, FieldType::Str, "target_name" },
    { 5, FieldType::Str, "text2" },
    { 6, FieldType::Str, "text3" },
    { 7, FieldType::Str, "name2" },
    { 8, FieldType::Str, "text4" },
};
constexpr FieldSpec kF_7D[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U64, "obj_id" },
    { 10, FieldType::U64, "action" },
    { 18, FieldType::U8, "class" },
    { 19, FieldType::U32, "time_ms" },
    { 23, FieldType::U8, "sub_type" },
    { 24, FieldType::Str, "name" },
};
constexpr FieldSpec kF_80[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_81[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "kind" },
    { 3, FieldType::U32, "target_id" },
    { 7, FieldType::U8, "action" },
    { 8, FieldType::U8, "action" },
    { 9, FieldType::U32, "obj_id" },
    { 13, FieldType::U32, "action" },
    { 17, FieldType::U8, "sub_type" },
    { 18, FieldType::U8, "obj_id" },
    { 19, FieldType::U8, "field_19" },
    { 20, FieldType::U16, "field_20" },
    { 22, FieldType::U16, "field_22" },
    { 24, FieldType::U16, "field_24" },
    { 26, FieldType::U16, "field_26" },
    { 28, FieldType::Str, "text" },
    { 33, FieldType::U8, "field_33" },
    { 67, FieldType::U8, "field_67" },
};
constexpr FieldSpec kF_82[] = {
    { 1, FieldType::U8, "msg_type" },
    { 2, FieldType::U8, "msg_index" },
};
constexpr FieldSpec kF_84[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U64, "sub_action" },
    { 10, FieldType::U64, "x" },
    { 18, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_83[] = {
    { 1, FieldType::U8, "action" },
    { 2, FieldType::U8, "flag" },
    { 6, FieldType::U16, "sub_value" },
    { 10, FieldType::U16, "field_10" },
    { 45, FieldType::U8, "field_45" },
    { 50, FieldType::U16, "field_50" },
    { 90, FieldType::U16, "field_90" },
    { 91, FieldType::U16, "field_91" },
    { 131, FieldType::U16, "field_131" },
};
constexpr FieldSpec kF_85[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U16, "count" },
    { 5, FieldType::U32, "amount" },
    { 9, FieldType::U8, "sub_type" },
    { 10, FieldType::U8, "char_id" },
    { 100, FieldType::U8, "action" },
    { 101, FieldType::Str, "name" },
    { 102, FieldType::Str, "name2" },
    { 103, FieldType::Str, "name3" },
    { 104, FieldType::Str, "name4" },
    { 105, FieldType::Str, "name5" },
    { 106, FieldType::Str, "name6" },
    { 107, FieldType::U16, "field_107" },
    { 109, FieldType::U16, "field_109" },
    { 111, FieldType::U8, "field_111" },
};
constexpr FieldSpec kF_86[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "kind" },
    { 3, FieldType::U16, "char_id" },
    { 5, FieldType::U8, "type" },
    { 37, FieldType::U8, "field_37" },
    { 133, FieldType::U8, "field_133" },
    { 134, FieldType::Str, "name" },
    { 135, FieldType::Str, "name2" },
    { 136, FieldType::Str, "name3" },
    { 137, FieldType::Str, "name4" },
    { 138, FieldType::Str, "name5" },
};
constexpr FieldSpec kF_87[] = {
    { 1, FieldType::U8, "flag_a" },
    { 2, FieldType::U8, "flag_b" },
    { 3, FieldType::U32, "char_id" },
};
constexpr FieldSpec kF_88[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_8B[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "slot" },
};
constexpr FieldSpec kF_8D[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U32, "char_id" },
    { 6, FieldType::U8, "type" },
    { 7, FieldType::U8, "ip_b1" },
    { 8, FieldType::U8, "ip_b2" },
    { 9, FieldType::U8, "ip_b3" },
    { 10, FieldType::U32, "ip_address" },
};
constexpr FieldSpec kF_90[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U32, "x" },
    { 6, FieldType::U32, "z" },
};
constexpr FieldSpec kF_91[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_92[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "sub_cmd" },
    { 3, FieldType::U64, "object_id" },
    { 11, FieldType::U8, "flag" },
    { 12, FieldType::U32, "value" },
    { 16, FieldType::U16, "field_16" },
    { 18, FieldType::U16, "field_18" },
    { 20, FieldType::U8, "field_20" },
    { 21, FieldType::U32, "field_21" },
};
constexpr FieldSpec kF_95[] = {
    { 1, FieldType::U32, "msg_id" },
    { 5, FieldType::U16, "msg_type" },
    { 7, FieldType::U16, "sub_type" },
    { 9, FieldType::U16, "name_len" },
    { 11, FieldType::Str, "name" },
    { 12, FieldType::U16, "time" },
    { 14, FieldType::U8, "type" },
    { 15, FieldType::U8, "type" },
    { 16, FieldType::U16, "value" },
    { 18, FieldType::U16, "value2" },
    { 20, FieldType::U8, "value" },
    { 55, FieldType::U8, "value2" },
    { 79, FieldType::U8, "field_79" },
    { 2863, FieldType::U8, "field_2863" },
    { 2867, FieldType::U8, "field_2867" },
};
constexpr FieldSpec kF_97[] = {
    { 1, FieldType::U16, "sub_type" },
    { 3, FieldType::U16, "value" },
};
constexpr FieldSpec kF_98[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_99[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "target_id" },
    { 3, FieldType::U16, "count" },
    { 5, FieldType::U16, "count" },
    { 7, FieldType::U16, "obj_id" },
    { 9, FieldType::U8, "flag" },
    { 10, FieldType::U32, "sub_type" },
    { 12, FieldType::U16, "count" },
    { 15, FieldType::U16, "count" },
    { 17, FieldType::U8, "count" },
    { 19, FieldType::U16, "field_19" },
    { 21, FieldType::U16, "field_21" },
    { 23, FieldType::U16, "field_23" },
    { 25, FieldType::U16, "field_25" },
    { 27, FieldType::Str, "field_27" },
    { 28, FieldType::U16, "field_28" },
    { 29, FieldType::U8, "field_29" },
    { 30, FieldType::U16, "field_30" },
    { 32, FieldType::U16, "field_32" },
    { 34, FieldType::U8, "field_34" },
    { 35, FieldType::U8, "field_35" },
    { 36, FieldType::U16, "field_36" },
};
constexpr FieldSpec kF_9A[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U8, "mode" },
    { 4, FieldType::U8, "flag2" },
    { 5, FieldType::U16, "x" },
    { 7, FieldType::U16, "z" },
};
constexpr FieldSpec kF_9B[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_9C[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_A0[] = {
    { 1, FieldType::U16, "field_1" },
    { 3, FieldType::Str, "field_3" },
};
constexpr FieldSpec kF_A5[] = {
    { 1, FieldType::U32, "value" },
};
constexpr FieldSpec kF_A9[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U32, "item_id" },
    { 6, FieldType::U16, "type" },
    { 8, FieldType::U16, "time" },
    { 33, FieldType::U8, "field_33" },
    { 41, FieldType::U16, "field_41" },
    { 43, FieldType::U16, "field_43" },
    { 45, FieldType::U16, "field_45" },
    { 47, FieldType::U8, "field_47" },
    { 52, FieldType::U16, "field_52" },
    { 56, FieldType::U16, "field_56" },
    { 58, FieldType::U8, "field_58" },
    { 60, FieldType::U16, "field_60" },
    { 62, FieldType::U16, "field_62" },
    { 64, FieldType::U16, "field_64" },
    { 66, FieldType::U16, "field_66" },
    { 68, FieldType::Str, "field_68" },
    { 69, FieldType::U16, "field_69" },
    { 70, FieldType::U8, "field_70" },
    { 71, FieldType::U16, "field_71" },
    { 73, FieldType::U16, "field_73" },
    { 75, FieldType::U8, "field_75" },
    { 76, FieldType::U8, "field_76" },
};
constexpr FieldSpec kF_AC[] = {
    { 1, FieldType::U8, "kind" },
    { 2, FieldType::U8, "sub_type" },
    { 3, FieldType::U32, "obj_id" },
    { 7, FieldType::U32, "value" },
    { 38, FieldType::U16, "field_38" },
};
constexpr FieldSpec kF_B5[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "name_len" },
    { 3, FieldType::Str, "name" },
    { 4, FieldType::Str, "char_id" },
    { 5, FieldType::Str, "pass_len" },
    { 6, FieldType::Str, "pass" },
    { 7, FieldType::Str, "title_len" },
    { 8, FieldType::Str, "title" },
    { 9, FieldType::U8, "flag" },
};
constexpr FieldSpec kF_B6[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "sub_type" },
    { 3, FieldType::U8, "count" },
    { 4, FieldType::U8, "field_4" },
    { 5, FieldType::U8, "field_5" },
    { 6, FieldType::U8, "field_6" },
    { 28, FieldType::U8, "field_28" },
    { 30, FieldType::U16, "field_30" },
    { 32, FieldType::U8, "name_len" },
};
constexpr FieldSpec kF_B7[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_B8[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "item_id" },
};
constexpr FieldSpec kF_B9[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "sub_type" },
    { 3, FieldType::U16, "category" },
    { 4, FieldType::U16, "action" },
};
constexpr FieldSpec kF_BD[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_C0[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_C2[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "slot" },
    { 4, FieldType::U8, "item_id" },
    { 5, FieldType::U8, "item_count" },
    { 6, FieldType::U8, "count" },
    { 7, FieldType::U8, "name_count" },
};
constexpr FieldSpec kF_C3[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U64, "result_code" },
    { 10, FieldType::U8, "type" },
    { 11, FieldType::U64, "obj_id" },
    { 19, FieldType::U8, "count" },
    { 947, FieldType::U8, "field_947" },
    { 951, FieldType::U8, "field_951" },
    { 959, FieldType::Str, "field_959" },
    { 960, FieldType::U8, "field_960" },
    { 968, FieldType::Str, "field_968" },
    { 969, FieldType::Str, "field_969" },
    { 970, FieldType::Str, "field_970" },
    { 971, FieldType::Str, "field_971" },
    { 972, FieldType::Str, "field_972" },
    { 973, FieldType::U8, "field_973" },
    { 978, FieldType::U8, "field_978" },
};
constexpr FieldSpec kF_C5[] = {
    { 1, FieldType::U8, "count" },
    { 2, FieldType::U16, "rank" },
    { 4, FieldType::U16, "rank_mark" },
    { 114, FieldType::U16, "rank_mark" },
    { 116, FieldType::U16, "rank_mark" },
    { 118, FieldType::U16, "rank_mark" },
    { 153, FieldType::U16, "rank" },
    { 155, FieldType::U16, "count" },
};
constexpr FieldSpec kF_C7[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "flag" },
    { 3, FieldType::U32, "value" },
    { 7, FieldType::U16, "count" },
    { 9, FieldType::U8, "flag2" },
    { 10, FieldType::U8, "flag3" },
    { 11, FieldType::U32, "kind" },
    { 15, FieldType::U16, "count2" },
};
constexpr FieldSpec kF_C8[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_CB[] = {
    { 1, FieldType::U32, "value" },
};
constexpr FieldSpec kF_CC[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_CE[] = {
    { 1, FieldType::U16, "type" },
    { 3, FieldType::U16, "type" },
    { 38, FieldType::U16, "type" },
};
constexpr FieldSpec kF_CF[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "sub_type" },
    { 3, FieldType::U8, "slot" },
    { 10, FieldType::U16, "sub_action" },
    { 11, FieldType::U8, "action" },
    { 15, FieldType::U8, "value" },
    { 35, FieldType::Str, "field_35" },
};
constexpr FieldSpec kF_D0[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_D1[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_D3[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "mode" },
    { 3, FieldType::U32, "value1" },
    { 7, FieldType::U32, "value2" },
    { 11, FieldType::U32, "value3" },
    { 15, FieldType::U32, "value4" },
};
constexpr FieldSpec kF_D5[] = {
    { 1, FieldType::U16, "header" },
    { 3, FieldType::U8, "flag1" },
    { 4, FieldType::U8, "flag2" },
    { 5, FieldType::U16, "header2" },
    { 7, FieldType::U16, "count" },
    { 9, FieldType::U8, "name_len" },
    { 10, FieldType::U16, "value_a" },
    { 12, FieldType::U16, "value_b" },
    { 14, FieldType::U8, "flag3" },
    { 15, FieldType::U8, "flag4" },
    { 16, FieldType::U32, "value_c" },
    { 20, FieldType::U32, "value_d" },
    { 42, FieldType::U16, "field_42" },
};
constexpr FieldSpec kF_D6[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_D7[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U32, "target_id" },
    { 6, FieldType::U32, "count" },
    { 10, FieldType::U16, "value" },
};
constexpr FieldSpec kF_D9[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U16, "sub_type" },
    { 4, FieldType::Str, "text" },
};

// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_01 = { 0x01, "WIZ_LOGIN_UNVERIFIED", Direction::In, kF_01, 4, true, false, true, true };
constexpr OpcodeInfo kI_02 = { 0x02, "WIZ_NEW_CHAR", Direction::In, kF_02, 9, false, false, false, false };
constexpr OpcodeInfo kI_03 = { 0x03, "WIZ_DEL_CHAR", Direction::In, kF_03, 15, false, false, false, false };
constexpr OpcodeInfo kI_04 = { 0x04, "WIZ_SEL_CHAR", Direction::In, kF_04, 20, false, false, true, false };
constexpr OpcodeInfo kI_05 = { 0x05, "WIZ_SEL_NATION", Direction::In, kF_05, 18, false, false, false, false };
constexpr OpcodeInfo kI_06 = { 0x06, "WIZ_MOVE", Direction::In, kF_06, 6, false, false, false, false };
constexpr OpcodeInfo kI_07 = { 0x07, "WIZ_USER_INOUT", Direction::In, kF_07, 23, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_08 = { 0x08, "WIZ_ATTACK_UNVERIFIED", Direction::In, kF_08, 4, true, false, false, false };
constexpr OpcodeInfo kI_09 = { 0x09, "WIZ_ROTATE", Direction::In, kF_09, 42, false, false, false, false };
constexpr OpcodeInfo kI_0A = { 0x0A, "WIZ_NPC_INOUT", Direction::In, kF_0A, 13, false, false, false, true };
constexpr OpcodeInfo kI_0B = { 0x0B, "WIZ_NPC_MOVE", Direction::In, kF_0B, 6, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_0C = { 0x0C, "WIZ_ALLCHAR_INFO_REQ_UNVERIFIED", Direction::In, kF_0C, 1, true, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_0D = { 0x0D, "WIZ_GAMESTART_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_0E = { 0x0E, "WIZ_MYINFO", Direction::In, kF_0E, 22, false, false, false, false };
constexpr OpcodeInfo kI_10 = { 0x10, "WIZ_CHAT", Direction::In, kF_10, 39, false, false, false, false };
constexpr OpcodeInfo kI_11 = { 0x11, "WIZ_DEAD", Direction::In, kF_11, 5, false, false, false, false };
constexpr OpcodeInfo kI_12 = { 0x12, "WIZ_REGENE", Direction::In, kF_12, 19, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_14 = { 0x14, "WIZ_WEATHER_UNVERIFIED", Direction::In, kF_14, 2, true, false, false, false };
constexpr OpcodeInfo kI_15 = { 0x15, "WIZ_REGIONCHANGE", Direction::In, kF_15, 29, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_16 = { 0x16, "WIZ_REQ_USERIN_UNVERIFIED", Direction::In, kF_16, 1, true, false, false, false };
constexpr OpcodeInfo kI_17 = { 0x17, "WIZ_HP_CHANGE", Direction::In, kF_17, 8, false, false, false, false };
constexpr OpcodeInfo kI_18 = { 0x18, "WIZ_MSP_CHANGE", Direction::In, kF_18, 7, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_19 = { 0x19, "WIZ_ITEM_LOG_UNVERIFIED", Direction::In, kF_19, 1, true, false, false, true };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_1A = { 0x1A, "WIZ_EXP_CHANGE_UNVERIFIED", Direction::In, kF_1A, 4, true, false, false, false };
constexpr OpcodeInfo kI_1B = { 0x1B, "WIZ_LEVEL_CHANGE", Direction::In, kF_1B, 13, false, false, false, false };
constexpr OpcodeInfo kI_1C = { 0x1C, "WIZ_NPC_REGION", Direction::In, kF_1C, 11, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_1D = { 0x1D, "WIZ_REQ_NPCIN_UNVERIFIED", Direction::In, kF_1D, 1, true, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_1E = { 0x1E, "WIZ_WARP_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_1F = { 0x1F, "WIZ_ITEM_MOVE_UNVERIFIED", Direction::In, kF_1F, 8, true, false, false, false };
constexpr OpcodeInfo kI_20 = { 0x20, "WIZ_NPC_EVENT", Direction::In, kF_20, 9, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_21 = { 0x21, "WIZ_ITEM_TRADE_UNVERIFIED", Direction::In, kF_21, 5, true, false, false, false };
constexpr OpcodeInfo kI_22 = { 0x22, "WIZ_TARGET_HP", Direction::In, kF_22, 7, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_23 = { 0x23, "WIZ_ITEM_DROP_UNVERIFIED", Direction::In, kF_23, 3, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_24 = { 0x24, "WIZ_BUNDLE_OPEN_REQ_UNVERIFIED", Direction::In, kF_24, 4, true, false, false, false };
constexpr OpcodeInfo kI_25 = { 0x25, "WIZ_TRADE_NPC", Direction::In, kF_25, 6, false, false, false, false };
constexpr OpcodeInfo kI_26 = { 0x26, "WIZ_ITEM_GET", Direction::In, kF_26, 8, false, false, false, false };
constexpr OpcodeInfo kI_27 = { 0x27, "WIZ_ZONE_CHANGE", Direction::In, nullptr, 0, false, false, false, false };
constexpr OpcodeInfo kI_28 = { 0x28, "WIZ_POINT_CHANGE", Direction::In, kF_28, 7, false, false, false, false };
constexpr OpcodeInfo kI_29 = { 0x29, "WIZ_STATE_CHANGE", Direction::In, kF_29, 3, false, false, false, false };
constexpr OpcodeInfo kI_2A = { 0x2A, "WIZ_LOYALTY_CHANGE", Direction::In, kF_2A, 5, false, false, false, false };
constexpr OpcodeInfo kI_2B = { 0x2B, "WIZ_VERSION_CHECK", Direction::In, nullptr, 0, false, false, true, false };
constexpr OpcodeInfo kI_2D = { 0x2D, "WIZ_USERLOOK_CHANGE", Direction::In, kF_2D, 17, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_2E = { 0x2E, "WIZ_NOTICE_UNVERIFIED", Direction::In, kF_2E, 1, true, false, false, false };
constexpr OpcodeInfo kI_2F = { 0x2F, "WIZ_PARTY", Direction::In, kF_2F, 23, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_30 = { 0x30, "WIZ_EXCHANGE_UNVERIFIED", Direction::In, kF_30, 15, true, false, false, false };
constexpr OpcodeInfo kI_31 = { 0x31, "WIZ_MAGIC_PROCESS", Direction::In, kF_31, 6, false, false, false, false };
constexpr OpcodeInfo kI_33 = { 0x33, "WIZ_OBJECT_EVENT", Direction::In, kF_33, 6, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_34 = { 0x34, "WIZ_CLASS_CHANGE_UNVERIFIED", Direction::In, kF_34, 3, true, false, false, false };
constexpr OpcodeInfo kI_35 = { 0x35, "WIZ_CHAT_TARGET", Direction::In, kF_35, 6, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_36 = { 0x36, "WIZ_CONCURRENTUSER_UNVERIFIED", Direction::In, kF_36, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_38 = { 0x38, "WIZ_DURATION_UNVERIFIED", Direction::In, kF_38, 2, true, false, false, false };
constexpr OpcodeInfo kI_3A = { 0x3A, "WIZ_REPAIR_NPC", Direction::In, kF_3A, 8, false, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_3B = { 0x3B, "WIZ_ITEM_REPAIR_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_3C = { 0x3C, "WIZ_KNIGHTS_PROCESS", Direction::In, kF_3C, 7, false, false, false, false };
constexpr OpcodeInfo kI_3D = { 0x3D, "WIZ_ITEM_COUNT_CHANGE", Direction::In, kF_3D, 13, false, false, false, false };
constexpr OpcodeInfo kI_3E = { 0x3E, "WIZ_KNIGHTS_LIST", Direction::In, kF_3E, 10, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_3F = { 0x3F, "WIZ_ITEM_REMOVE_UNVERIFIED", Direction::In, kF_3F, 2, true, false, false, false };
constexpr OpcodeInfo kI_40 = { 0x40, "WIZ_OPERATOR", Direction::In, kF_40, 12, false, false, false, false };
constexpr OpcodeInfo kI_42 = { 0x42, "WIZ_COMPRESS_PACKET", Direction::In, nullptr, 0, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_44 = { 0x44, "WIZ_CONTINOUS_PACKET_UNVERIFIED", Direction::In, kF_44, 5, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_45 = { 0x45, "WIZ_WAREHOUSE_UNVERIFIED", Direction::In, kF_45, 8, true, false, false, false };
constexpr OpcodeInfo kI_46 = { 0x46, "WIZ_SERVER_CHANGE", Direction::In, kF_46, 2, false, false, true, false };
constexpr OpcodeInfo kI_49 = { 0x49, "WIZ_FRIEND_PROCESS", Direction::In, kF_49, 9, false, false, false, false };
constexpr OpcodeInfo kI_4A = { 0x4A, "WIZ_GOLD_CHANGE", Direction::In, kF_4A, 5, false, false, false, false };
constexpr OpcodeInfo kI_4B = { 0x4B, "WIZ_WARP_LIST", Direction::In, kF_4B, 12, false, false, false, false };
constexpr OpcodeInfo kI_4E = { 0x4E, "WIZ_CORPSE", Direction::In, kF_4E, 23, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_4F = { 0x4F, "WIZ_PARTY_BBS_UNVERIFIED", Direction::In, kF_4F, 1, true, false, false, false };
constexpr OpcodeInfo kI_50 = { 0x50, "WIZ_MARKET_BBS", Direction::In, kF_50, 5, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_53 = { 0x53, "WIZ_MAP_EVENT_UNVERIFIED", Direction::In, kF_53, 6, true, false, false, false };
constexpr OpcodeInfo kI_54 = { 0x54, "WIZ_WEIGHT_CHANGE", Direction::In, kF_54, 17, false, false, false, false };
constexpr OpcodeInfo kI_55 = { 0x55, "WIZ_SELECT_MSG", Direction::In, kF_55, 4, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_57 = { 0x57, "WIZ_BATTLE_EVENT_UNVERIFIED", Direction::In, kF_57, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_58 = { 0x58, "WIZ_AUTHORITY_CHANGE_UNVERIFIED", Direction::In, kF_58, 3, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_59 = { 0x59, "WIZ_EDIT_BOX_UNVERIFIED", Direction::In, kF_59, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_5A = { 0x5A, "WIZ_SANTA_UNVERIFIED", Direction::In, kF_5A, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_5B = { 0x5B, "WIZ_ITEM_UPGRADE_UNVERIFIED", Direction::In, kF_5B, 1, true, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_5D = { 0x5D, "WIZ_PACKET2_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_5E = { 0x5E, "WIZ_ZONEABILITY_UNVERIFIED", Direction::In, kF_5E, 9, true, false, false, false };
constexpr OpcodeInfo kI_5F = { 0x5F, "WIZ_EVENT", Direction::In, kF_5F, 10, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_60 = { 0x60, "WIZ_STEALTH_UNVERIFIED", Direction::In, kF_60, 2, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_61 = { 0x61, "WIZ_ROOM_PACKETPROCESS_UNVERIFIED", Direction::In, kF_61, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_63 = { 0x63, "WIZ_PACKET3_UNVERIFIED", Direction::In, kF_63, 3, true, false, false, false };
constexpr OpcodeInfo kI_64 = { 0x64, "WIZ_QUEST", Direction::In, kF_64, 15, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_65 = { 0x65, "WIZ_PACKET4_UNVERIFIED", Direction::In, kF_65, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_66 = { 0x66, "WIZ_KISS_UNVERIFIED", Direction::In, kF_66, 2, true, false, false, false };
constexpr OpcodeInfo kI_68 = { 0x68, "WIZ_MERCHANT", Direction::In, kF_68, 2, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_69 = { 0x69, "WIZ_MERCHANT_INOUT_UNVERIFIED", Direction::In, kF_69, 16, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_6A = { 0x6A, "WIZ_SHOPPING_MALL_UNVERIFIED", Direction::In, kF_6A, 1, true, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_6B = { 0x6B, "WIZ_SERVER_INDEX_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_6C = { 0x6C, "WIZ_EFFECT", Direction::In, kF_6C, 17, false, false, false, false };
constexpr OpcodeInfo kI_6D = { 0x6D, "WIZ_SIEGE", Direction::In, kF_6D, 18, false, false, false, false };
constexpr OpcodeInfo kI_6E = { 0x6E, "WIZ_NAME_CHANGE", Direction::In, kF_6E, 14, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_70 = { 0x70, "WIZ_CAPE_UNVERIFIED", Direction::In, kF_70, 1, true, false, false, false };
constexpr OpcodeInfo kI_71 = { 0x71, "WIZ_PREMIUM", Direction::In, kF_71, 8, false, false, false, false };
constexpr OpcodeInfo kI_72 = { 0x72, "WIZ_HACKTOOL", Direction::In, nullptr, 0, false, false, true, false };
constexpr OpcodeInfo kI_73 = { 0x73, "WIZ_RENTAL", Direction::In, kF_73, 3, false, false, false, false };
constexpr OpcodeInfo kI_74 = { 0x74, "WIZ_PACKET5", Direction::In, kF_74, 6, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_75 = { 0x75, "WIZ_CHALLENGE_UNVERIFIED", Direction::In, kF_75, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_76 = { 0x76, "WIZ_PET_UNVERIFIED", Direction::In, kF_76, 7, true, false, false, false };
constexpr OpcodeInfo kI_78 = { 0x78, "WIZ_KING", Direction::In, kF_78, 4, false, false, false, false };
constexpr OpcodeInfo kI_79 = { 0x79, "WIZ_SKILLDATA", Direction::In, kF_79, 4, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_7A = { 0x7A, "WIZ_PROGRAMCHECK_UNVERIFIED", Direction::In, kF_7A, 1, true, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_7B = { 0x7B, "WIZ_BIFROST_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_7C = { 0x7C, "WIZ_REPORT", Direction::In, kF_7C, 8, false, false, false, false };
constexpr OpcodeInfo kI_7D = { 0x7D, "WIZ_LOGOSSHOUT", Direction::In, kF_7D, 7, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_80 = { 0x80, "WIZ_RANK_UNVERIFIED", Direction::In, kF_80, 1, true, false, false, false };
constexpr OpcodeInfo kI_81 = { 0x81, "WIZ_STORY", Direction::In, kF_81, 17, false, false, false, false };
constexpr OpcodeInfo kI_82 = { 0x82, "WIZ_PACKET8", Direction::In, kF_82, 2, false, false, false, false };
constexpr OpcodeInfo kI_83 = { 0x83, "WIZ_PACKET9", Direction::In, kF_83, 9, false, false, false, false };
constexpr OpcodeInfo kI_84 = { 0x84, "WIZ_PACKET10", Direction::In, kF_84, 4, false, false, false, false };
constexpr OpcodeInfo kI_85 = { 0x85, "WIZ_PACKET11", Direction::In, kF_85, 16, false, false, false, false };
constexpr OpcodeInfo kI_86 = { 0x86, "WIZ_MINING", Direction::In, kF_86, 11, false, false, false, false };
constexpr OpcodeInfo kI_87 = { 0x87, "WIZ_HELMET", Direction::In, kF_87, 3, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_88 = { 0x88, "WIZ_PVP_UNVERIFIED", Direction::In, kF_88, 1, true, false, false, false };
constexpr OpcodeInfo kI_89 = { 0x89, "WIZ_CHANGE_HAIR", Direction::In, nullptr, 0, false, false, true, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_8B = { 0x8B, "WIZ_PACKET13_UNVERIFIED", Direction::In, kF_8B, 2, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_8D = { 0x8D, "WIZ_PACKET15_UNVERIFIED", Direction::In, kF_8D, 7, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_90 = { 0x90, "WIZ_DEATH_LIST_UNVERIFIED", Direction::In, kF_90, 3, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_91 = { 0x91, "WIZ_CLANPOINTS_BATTLE_UNVERIFIED", Direction::In, kF_91, 2, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_92 = { 0x92, "OP_92_UNVERIFIED", Direction::In, kF_92, 9, true, false, false, false };
constexpr OpcodeInfo kI_95 = { 0x95, "OP_95", Direction::In, kF_95, 15, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_97 = { 0x97, "OP_97_UNVERIFIED", Direction::In, kF_97, 2, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_98 = { 0x98, "OP_98_UNVERIFIED", Direction::In, kF_98, 1, true, false, false, false };
constexpr OpcodeInfo kI_99 = { 0x99, "OP_99", Direction::In, kF_99, 22, false, false, false, false };
constexpr OpcodeInfo kI_9A = { 0x9A, "OP_9A", Direction::In, kF_9A, 6, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_9B = { 0x9B, "OP_9B_UNVERIFIED", Direction::In, kF_9B, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_9C = { 0x9C, "OP_9C_UNVERIFIED", Direction::In, kF_9C, 1, true, false, false, false };
constexpr OpcodeInfo kI_9F = { 0x9F, "OP_9F", Direction::In, nullptr, 0, false, false, true, false };
constexpr OpcodeInfo kI_A0 = { 0xA0, "WIZ_XINCODE", Direction::In, kF_A0, 2, false, false, true, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_A5 = { 0xA5, "OP_A5_UNVERIFIED", Direction::In, kF_A5, 1, true, false, false, false };
constexpr OpcodeInfo kI_A9 = { 0xA9, "OP_A9", Direction::In, kF_A9, 23, false, false, false, false };
constexpr OpcodeInfo kI_AC = { 0xAC, "OP_AC", Direction::In, kF_AC, 5, false, false, false, false };
// provisional: Handler govde okumuyor; islev yalnizca switch konumundan cikarildi, alan yok.
constexpr OpcodeInfo kI_B4 = { 0xB4, "OP_B4_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_B5 = { 0xB5, "OP_B5", Direction::In, kF_B5, 9, false, false, false, false };
constexpr OpcodeInfo kI_B6 = { 0xB6, "OP_B6", Direction::In, kF_B6, 9, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_B7 = { 0xB7, "OP_B7_UNVERIFIED", Direction::In, kF_B7, 1, true, false, false, false };
constexpr OpcodeInfo kI_B8 = { 0xB8, "OP_B8", Direction::In, kF_B8, 2, false, false, false, false };
constexpr OpcodeInfo kI_B9 = { 0xB9, "OP_B9", Direction::In, kF_B9, 4, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_BD = { 0xBD, "OP_BD_UNVERIFIED", Direction::In, kF_BD, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_C0 = { 0xC0, "OP_C0_UNVERIFIED", Direction::In, kF_C0, 1, true, false, false, false };
constexpr OpcodeInfo kI_C2 = { 0xC2, "OP_C2", Direction::In, kF_C2, 6, false, false, false, false };
constexpr OpcodeInfo kI_C3 = { 0xC3, "OP_C3", Direction::In, kF_C3, 16, false, false, false, false };
constexpr OpcodeInfo kI_C5 = { 0xC5, "OP_C5", Direction::In, kF_C5, 8, false, false, false, false };
constexpr OpcodeInfo kI_C7 = { 0xC7, "OP_C7", Direction::In, kF_C7, 8, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_C8 = { 0xC8, "OP_C8_UNVERIFIED", Direction::In, kF_C8, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_CB = { 0xCB, "OP_CB_UNVERIFIED", Direction::In, kF_CB, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_CC = { 0xCC, "OP_CC_UNVERIFIED", Direction::In, kF_CC, 1, true, false, false, false };
constexpr OpcodeInfo kI_CE = { 0xCE, "OP_CE", Direction::In, kF_CE, 3, false, false, false, false };
constexpr OpcodeInfo kI_CF = { 0xCF, "OP_CF", Direction::In, kF_CF, 7, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_D0 = { 0xD0, "OP_D0_UNVERIFIED", Direction::In, kF_D0, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_D1 = { 0xD1, "OP_D1_UNVERIFIED", Direction::In, kF_D1, 1, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_D3 = { 0xD3, "OP_D3_UNVERIFIED", Direction::In, kF_D3, 6, true, false, false, false };
constexpr OpcodeInfo kI_D5 = { 0xD5, "OP_D5", Direction::In, kF_D5, 13, false, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_D6 = { 0xD6, "OP_D6_UNVERIFIED", Direction::In, kF_D6, 2, true, false, false, false };
// provisional: Alan sirasi handler okumalarindan cikarildi; alan anlamlari ve ad canli trafikle dogrulanmadi.
constexpr OpcodeInfo kI_D7 = { 0xD7, "OP_D7_UNVERIFIED", Direction::In, kF_D7, 4, true, false, false, false };
constexpr OpcodeInfo kI_D9 = { 0xD9, "OP_D9", Direction::In, kF_D9, 3, false, false, false, false };
constexpr OpcodeInfo kI_FE = { 0xFE, "OP_FE", Direction::In, nullptr, 0, false, false, true, false };

// ---------------------------------------------------------------------------
// GIDEN YON (pkt_send_wrap cagri yerleri)
//
// Her kayit bir cagri yerinden cikarildi: tamponun 0. WORD'une yazilan deger
// opcode (dusuk bayt) + varyant (yuksek bayt), sonraki yazimlar alanlardir.
// Opcode'un kendisi de tamponun 0. baytina yazilir; alanlar 1'den baslar.
// variant = true olan kayitlarda offset 1 alt secicidir (U8).
// ---------------------------------------------------------------------------
constexpr FieldSpec kF_O_05[] = {
    { 1, FieldType::U8, "obj_id" },
};
constexpr FieldSpec kF_O_0C[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_10[] = {
    { 1, FieldType::U8, "chat_type" },
};
constexpr FieldSpec kF_O_12[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_14[] = {
    { 1, FieldType::U8, "sound_type" },
};
constexpr FieldSpec kF_O_19[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_1E[] = {
    { 1, FieldType::U8, "field_1" },
    { 3, FieldType::U8, "field_3" },
};
constexpr FieldSpec kF_O_1F[] = {
    { 1, FieldType::U8, "update_type" },
    { 2, FieldType::U8, "flag" },
};
constexpr FieldSpec kF_O_20[] = {
    { 1, FieldType::U8, "sound_type" },
};
constexpr FieldSpec kF_O_21[] = {
    { 1, FieldType::U8, "type" },
};
constexpr FieldSpec kF_O_26[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "amount" },
    { 3, FieldType::U8, "field_3" },
};
constexpr FieldSpec kF_O_2F[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_30[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_32[] = {
    { 1, FieldType::U8, "field_1" },
};
constexpr FieldSpec kF_O_34[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U16, "sub_type" },
};
constexpr FieldSpec kF_O_35[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "target_id" },
};
constexpr FieldSpec kF_O_3B[] = {
    { 1, FieldType::U8, "type" },
    { 2, FieldType::U8, "slot" },
};
constexpr FieldSpec kF_O_3C[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "type" },
    { 3, FieldType::U8, "action" },
};
constexpr FieldSpec kF_O_40[] = {
    { 1, FieldType::U8, "type" },
};
constexpr FieldSpec kF_O_41[] = {
    { 1, FieldType::U8, "char_id" },
};
constexpr FieldSpec kF_O_49[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "name_len" },
};
constexpr FieldSpec kF_O_4F[] = {
    { 1, FieldType::U8, "state" },
    { 2, FieldType::U8, "field_2" },
    { 3, FieldType::U8, "field_3" },
};
constexpr FieldSpec kF_O_50[] = {
    { 1, FieldType::U8, "mode" },
    { 2, FieldType::U8, "side" },
    { 3, FieldType::U16, "flag" },
    { 5, FieldType::Str, "notice_type" },
};
constexpr FieldSpec kF_O_51[] = {
    { 1, FieldType::U16, "type" },
};
constexpr FieldSpec kF_O_55[] = {
    { 1, FieldType::U8, "obj_id" },
    { 2, FieldType::U8, "field_2" },
};
constexpr FieldSpec kF_O_57[] = {
    { 1, FieldType::U8, "sub_opcode" },
    { 2, FieldType::U16, "field_2" },
};
constexpr FieldSpec kF_O_5B[] = {
    { 1, FieldType::U8, "value" },
    { 2, FieldType::U32, "field_2" },
    { 6, FieldType::U8, "field_6" },
    { 7, FieldType::U32, "field_7" },
};
constexpr FieldSpec kF_O_5F[] = {
    { 1, FieldType::U8, "kind" },
    { 2, FieldType::U16, "action" },
};
constexpr FieldSpec kF_O_61[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "result" },
};
constexpr FieldSpec kF_O_62[] = {
    { 1, FieldType::U8, "field_1" },
};
constexpr FieldSpec kF_O_68[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "state" },
};
constexpr FieldSpec kF_O_6A[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_O_6D[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "state" },
};
constexpr FieldSpec kF_O_6E[] = {
    { 2, FieldType::U16, "name_len" },
    { 4, FieldType::Str, "name" },
};
constexpr FieldSpec kF_O_70[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_72[] = {
    { 1, FieldType::U8, "field_1" },
    { 2, FieldType::U16, "field_2" },
};
constexpr FieldSpec kF_O_73[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_75[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_77[] = {
    { 1, FieldType::U8, "field_1" },
    { 4, FieldType::U8, "field_4" },
    { 5, FieldType::Str, "field_5" },
};
constexpr FieldSpec kF_O_78[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U8, "name" },
    { 3, FieldType::U32, "sub_type" },
    { 7, FieldType::U8, "field_7" },
};
constexpr FieldSpec kF_O_79[] = {
    { 1, FieldType::U8, "state" },
};
constexpr FieldSpec kF_O_7A[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_O_7C[] = {
    { 1, FieldType::U8, "sub_type" },
    { 3, FieldType::Str, "message" },
};
constexpr FieldSpec kF_O_7D[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_84[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_85[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_89[] = {
    { 1, FieldType::U8, "sub_opcode" },
};
constexpr FieldSpec kF_O_98[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_99[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "target_id" },
};
constexpr FieldSpec kF_O_9A[] = {
    { 1, FieldType::U8, "sub_type" },
};
constexpr FieldSpec kF_O_9C[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_O_AC[] = {
    { 1, FieldType::U8, "kind" },
};
constexpr FieldSpec kF_O_B5[] = {
    { 1, FieldType::U8, "sub_type" },
    { 2, FieldType::U16, "name_len" },
};
constexpr FieldSpec kF_O_B9[] = {
    { 1, FieldType::U8, "type" },
};
constexpr FieldSpec kF_O_CC[] = {
    { 1, FieldType::U8, "value" },
};
constexpr FieldSpec kF_O_CF[] = {
    { 1, FieldType::U8, "type" },
};
constexpr FieldSpec kF_O_D5[] = {
    { 1, FieldType::U8, "header" },
    { 2, FieldType::U8, "field_2" },
};
constexpr FieldSpec kF_O_F9[] = {
    { 1, FieldType::U16, "field_1" },
    { 3, FieldType::U16, "field_3" },
    { 5, FieldType::U16, "field_5" },
    { 7, FieldType::Str, "field_7" },
};

// Adlar ayni opcode'un alim kaydindan turetildi; govde okumayan cagri
// yerlerinde "_UNVERIFIED" soneki ve provisional = true birakildi.
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_01 = { 0x01, "WIZ_LOGIN_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kO_05 = { 0x05, "WIZ_SEL_NATION_OUT", Direction::Out, kF_O_05, 1, false, false, false, false };
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_09 = { 0x09, "WIZ_ROTATE_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kO_0C = { 0x0C, "WIZ_ALLCHAR_INFO_REQ_OUT", Direction::Out, kF_O_0C, 1, false, false, false, true };
constexpr OpcodeInfo kO_10 = { 0x10, "WIZ_CHAT_OUT", Direction::Out, kF_O_10, 1, false, false, false, false };
constexpr OpcodeInfo kO_12 = { 0x12, "WIZ_REGENE_OUT", Direction::Out, kF_O_12, 1, false, false, false, false };
constexpr OpcodeInfo kO_14 = { 0x14, "WIZ_WEATHER_OUT", Direction::Out, kF_O_14, 1, false, false, false, false };
constexpr OpcodeInfo kO_19 = { 0x19, "WIZ_ITEM_LOG_OUT", Direction::Out, kF_O_19, 1, false, false, false, true };
constexpr OpcodeInfo kO_1E = { 0x1E, "WIZ_WARP_OUT", Direction::Out, kF_O_1E, 2, false, false, false, false };
constexpr OpcodeInfo kO_1F = { 0x1F, "WIZ_ITEM_MOVE_OUT", Direction::Out, kF_O_1F, 2, false, false, false, false };
constexpr OpcodeInfo kO_20 = { 0x20, "WIZ_NPC_EVENT_OUT", Direction::Out, kF_O_20, 1, false, false, false, false };
constexpr OpcodeInfo kO_21 = { 0x21, "WIZ_ITEM_TRADE_OUT", Direction::Out, kF_O_21, 1, false, false, false, true };
constexpr OpcodeInfo kO_26 = { 0x26, "WIZ_ITEM_GET_OUT", Direction::Out, kF_O_26, 3, false, false, false, false };
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_2B = { 0x2B, "WIZ_VERSION_CHECK_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kO_2F = { 0x2F, "WIZ_PARTY_OUT", Direction::Out, kF_O_2F, 1, false, false, false, true };
constexpr OpcodeInfo kO_30 = { 0x30, "WIZ_EXCHANGE_OUT", Direction::Out, kF_O_30, 1, false, false, false, true };
constexpr OpcodeInfo kO_32 = { 0x32, "OP_32_OUT", Direction::Out, kF_O_32, 1, false, false, false, false };
constexpr OpcodeInfo kO_34 = { 0x34, "WIZ_CLASS_CHANGE_OUT", Direction::Out, kF_O_34, 2, false, false, false, true };
constexpr OpcodeInfo kO_35 = { 0x35, "WIZ_CHAT_TARGET_OUT", Direction::Out, kF_O_35, 2, false, false, false, true };
constexpr OpcodeInfo kO_3B = { 0x3B, "WIZ_ITEM_REPAIR_OUT", Direction::Out, kF_O_3B, 2, false, false, false, false };
constexpr OpcodeInfo kO_3C = { 0x3C, "WIZ_KNIGHTS_PROCESS_OUT", Direction::Out, kF_O_3C, 3, false, false, false, true };
constexpr OpcodeInfo kO_40 = { 0x40, "WIZ_OPERATOR_OUT", Direction::Out, kF_O_40, 1, false, false, false, false };
constexpr OpcodeInfo kO_41 = { 0x41, "OP_41_OUT", Direction::Out, kF_O_41, 1, false, false, false, false };
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_48 = { 0x48, "OP_48_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kO_49 = { 0x49, "WIZ_FRIEND_PROCESS_OUT", Direction::Out, kF_O_49, 2, false, false, false, true };
constexpr OpcodeInfo kO_4F = { 0x4F, "WIZ_PARTY_BBS_OUT", Direction::Out, kF_O_4F, 3, false, false, false, false };
constexpr OpcodeInfo kO_50 = { 0x50, "WIZ_MARKET_BBS_OUT", Direction::Out, kF_O_50, 4, false, false, false, true };
constexpr OpcodeInfo kO_51 = { 0x51, "OP_51_OUT", Direction::Out, kF_O_51, 1, false, false, false, false };
constexpr OpcodeInfo kO_55 = { 0x55, "WIZ_SELECT_MSG_OUT", Direction::Out, kF_O_55, 2, false, false, false, false };
constexpr OpcodeInfo kO_57 = { 0x57, "WIZ_BATTLE_EVENT_OUT", Direction::Out, kF_O_57, 2, false, false, false, true };
constexpr OpcodeInfo kO_5B = { 0x5B, "WIZ_ITEM_UPGRADE_OUT", Direction::Out, kF_O_5B, 4, false, false, false, true };
constexpr OpcodeInfo kO_5F = { 0x5F, "WIZ_EVENT_OUT", Direction::Out, kF_O_5F, 2, false, false, false, true };
constexpr OpcodeInfo kO_61 = { 0x61, "WIZ_ROOM_PACKETPROCESS_OUT", Direction::Out, kF_O_61, 2, false, false, false, true };
constexpr OpcodeInfo kO_62 = { 0x62, "OP_62_OUT", Direction::Out, kF_O_62, 1, false, false, false, false };
constexpr OpcodeInfo kO_68 = { 0x68, "WIZ_MERCHANT_OUT", Direction::Out, kF_O_68, 2, false, false, false, true };
constexpr OpcodeInfo kO_6A = { 0x6A, "WIZ_SHOPPING_MALL_OUT", Direction::Out, kF_O_6A, 1, false, false, false, true };
constexpr OpcodeInfo kO_6D = { 0x6D, "WIZ_SIEGE_OUT", Direction::Out, kF_O_6D, 2, false, false, false, true };
constexpr OpcodeInfo kO_6E = { 0x6E, "WIZ_NAME_CHANGE_OUT", Direction::Out, kF_O_6E, 2, false, false, false, false };
constexpr OpcodeInfo kO_70 = { 0x70, "WIZ_CAPE_OUT", Direction::Out, kF_O_70, 1, false, false, false, false };
constexpr OpcodeInfo kO_72 = { 0x72, "WIZ_HACKTOOL_OUT", Direction::Out, kF_O_72, 2, false, false, false, true };
constexpr OpcodeInfo kO_73 = { 0x73, "WIZ_RENTAL_OUT", Direction::Out, kF_O_73, 1, false, false, false, true };
constexpr OpcodeInfo kO_75 = { 0x75, "WIZ_CHALLENGE_OUT", Direction::Out, kF_O_75, 1, false, false, false, true };
constexpr OpcodeInfo kO_77 = { 0x77, "OP_77_OUT", Direction::Out, kF_O_77, 3, false, false, false, true };
constexpr OpcodeInfo kO_78 = { 0x78, "WIZ_KING_OUT", Direction::Out, kF_O_78, 4, false, false, false, true };
constexpr OpcodeInfo kO_79 = { 0x79, "WIZ_SKILLDATA_OUT", Direction::Out, kF_O_79, 1, false, false, false, true };
constexpr OpcodeInfo kO_7A = { 0x7A, "WIZ_PROGRAMCHECK_OUT", Direction::Out, kF_O_7A, 1, false, false, false, false };
constexpr OpcodeInfo kO_7C = { 0x7C, "WIZ_REPORT_OUT", Direction::Out, kF_O_7C, 2, false, false, false, true };
constexpr OpcodeInfo kO_7D = { 0x7D, "WIZ_LOGOSSHOUT_OUT", Direction::Out, kF_O_7D, 1, false, false, false, false };
constexpr OpcodeInfo kO_84 = { 0x84, "WIZ_PACKET10_OUT", Direction::Out, kF_O_84, 1, false, false, false, true };
constexpr OpcodeInfo kO_85 = { 0x85, "WIZ_PACKET11_OUT", Direction::Out, kF_O_85, 1, false, false, false, true };
constexpr OpcodeInfo kO_89 = { 0x89, "WIZ_CHANGE_HAIR_OUT", Direction::Out, kF_O_89, 1, false, false, false, true };
constexpr OpcodeInfo kO_98 = { 0x98, "OP_98_OUT", Direction::Out, kF_O_98, 1, false, false, false, true };
constexpr OpcodeInfo kO_99 = { 0x99, "OP_99_OUT", Direction::Out, kF_O_99, 2, false, false, false, true };
constexpr OpcodeInfo kO_9A = { 0x9A, "OP_9A_OUT", Direction::Out, kF_O_9A, 1, false, false, false, true };
constexpr OpcodeInfo kO_9C = { 0x9C, "OP_9C_OUT", Direction::Out, kF_O_9C, 1, false, false, false, true };
constexpr OpcodeInfo kO_AC = { 0xAC, "OP_AC_OUT", Direction::Out, kF_O_AC, 1, false, false, false, true };
constexpr OpcodeInfo kO_B5 = { 0xB5, "OP_B5_OUT", Direction::Out, kF_O_B5, 2, false, false, false, true };
constexpr OpcodeInfo kO_B9 = { 0xB9, "OP_B9_OUT", Direction::Out, kF_O_B9, 1, false, false, false, true };
constexpr OpcodeInfo kO_CC = { 0xCC, "OP_CC_OUT", Direction::Out, kF_O_CC, 1, false, false, false, true };
constexpr OpcodeInfo kO_CF = { 0xCF, "OP_CF_OUT", Direction::Out, kF_O_CF, 1, false, false, false, true };
constexpr OpcodeInfo kO_D5 = { 0xD5, "OP_D5_OUT", Direction::Out, kF_O_D5, 2, false, false, false, false };
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_F2 = { 0xF2, "OP_F2_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_F6 = { 0xF6, "OP_F6_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kO_F9 = { 0xF9, "OP_F9_OUT", Direction::Out, kF_O_F9, 4, false, false, false, false };
// provisional: Cagri yeri govdeye alan yazmiyor (sabit opcode); islev adi cagri yerinden turetildi.
constexpr OpcodeInfo kO_FD = { 0xFD, "OP_FD_OUT_UNVERIFIED", Direction::Out, nullptr, 0, true, false, false, false };

// 256 girisli indeksli tablo: bos slotlar nullptr. Ikili arama yok.
constexpr const OpcodeInfo* kInTable[256] = {
    /* 0x00 */ nullptr, &kI_01, &kI_02, &kI_03, &kI_04, &kI_05, &kI_06, &kI_07,
    /* 0x08 */ &kI_08, &kI_09, &kI_0A, &kI_0B, &kI_0C, &kI_0D, &kI_0E, nullptr,
    /* 0x10 */ &kI_10, &kI_11, &kI_12, nullptr, &kI_14, &kI_15, &kI_16, &kI_17,
    /* 0x18 */ &kI_18, &kI_19, &kI_1A, &kI_1B, &kI_1C, &kI_1D, &kI_1E, &kI_1F,
    /* 0x20 */ &kI_20, &kI_21, &kI_22, &kI_23, &kI_24, &kI_25, &kI_26, &kI_27,
    /* 0x28 */ &kI_28, &kI_29, &kI_2A, &kI_2B, nullptr, &kI_2D, &kI_2E, &kI_2F,
    /* 0x30 */ &kI_30, &kI_31, nullptr, &kI_33, &kI_34, &kI_35, &kI_36, nullptr,
    /* 0x38 */ &kI_38, nullptr, &kI_3A, &kI_3B, &kI_3C, &kI_3D, &kI_3E, &kI_3F,
    /* 0x40 */ &kI_40, nullptr, &kI_42, nullptr, &kI_44, &kI_45, &kI_46, nullptr,
    /* 0x48 */ nullptr, &kI_49, &kI_4A, &kI_4B, nullptr, nullptr, &kI_4E, &kI_4F,
    /* 0x50 */ &kI_50, nullptr, nullptr, &kI_53, &kI_54, &kI_55, nullptr, &kI_57,
    /* 0x58 */ &kI_58, &kI_59, &kI_5A, &kI_5B, nullptr, &kI_5D, &kI_5E, &kI_5F,
    /* 0x60 */ &kI_60, &kI_61, nullptr, &kI_63, &kI_64, &kI_65, &kI_66, nullptr,
    /* 0x68 */ &kI_68, &kI_69, &kI_6A, &kI_6B, &kI_6C, &kI_6D, &kI_6E, nullptr,
    /* 0x70 */ &kI_70, &kI_71, &kI_72, &kI_73, &kI_74, &kI_75, &kI_76, nullptr,
    /* 0x78 */ &kI_78, &kI_79, &kI_7A, &kI_7B, &kI_7C, &kI_7D, nullptr, nullptr,
    /* 0x80 */ &kI_80, &kI_81, &kI_82, &kI_83, &kI_84, &kI_85, &kI_86, &kI_87,
    /* 0x88 */ &kI_88, &kI_89, nullptr, &kI_8B, nullptr, &kI_8D, nullptr, nullptr,
    /* 0x90 */ &kI_90, &kI_91, &kI_92, nullptr, nullptr, &kI_95, nullptr, &kI_97,
    /* 0x98 */ &kI_98, &kI_99, &kI_9A, &kI_9B, &kI_9C, nullptr, nullptr, &kI_9F,
    /* 0xA0 */ &kI_A0, nullptr, nullptr, nullptr, nullptr, &kI_A5, nullptr, nullptr,
    /* 0xA8 */ nullptr, &kI_A9, nullptr, nullptr, &kI_AC, nullptr, nullptr, nullptr,
    /* 0xB0 */ nullptr, nullptr, nullptr, nullptr, &kI_B4, &kI_B5, &kI_B6, &kI_B7,
    /* 0xB8 */ &kI_B8, &kI_B9, nullptr, nullptr, nullptr, &kI_BD, nullptr, nullptr,
    /* 0xC0 */ &kI_C0, nullptr, &kI_C2, &kI_C3, nullptr, &kI_C5, nullptr, &kI_C7,
    /* 0xC8 */ &kI_C8, nullptr, nullptr, &kI_CB, &kI_CC, nullptr, &kI_CE, &kI_CF,
    /* 0xD0 */ &kI_D0, &kI_D1, nullptr, &kI_D3, nullptr, &kI_D5, &kI_D6, &kI_D7,
    /* 0xD8 */ nullptr, &kI_D9, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xE0 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xE8 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xF0 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xF8 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &kI_FE, nullptr,
};

// Giden yon tablosu: pkt_send_wrap cagri yerlerinden cikarildi.
constexpr const OpcodeInfo* kOutTable[256] = {
    /* 0x00 */ nullptr, &kO_01, nullptr, nullptr, nullptr, &kO_05, nullptr, nullptr,
    /* 0x08 */ nullptr, &kO_09, nullptr, nullptr, &kO_0C, nullptr, nullptr, nullptr,
    /* 0x10 */ &kO_10, nullptr, &kO_12, nullptr, &kO_14, nullptr, nullptr, nullptr,
    /* 0x18 */ nullptr, &kO_19, nullptr, nullptr, nullptr, nullptr, &kO_1E, &kO_1F,
    /* 0x20 */ &kO_20, &kO_21, nullptr, nullptr, nullptr, nullptr, &kO_26, nullptr,
    /* 0x28 */ nullptr, nullptr, nullptr, &kO_2B, nullptr, nullptr, nullptr, &kO_2F,
    /* 0x30 */ &kO_30, nullptr, &kO_32, nullptr, &kO_34, &kO_35, nullptr, nullptr,
    /* 0x38 */ nullptr, nullptr, nullptr, &kO_3B, &kO_3C, nullptr, nullptr, nullptr,
    /* 0x40 */ &kO_40, &kO_41, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0x48 */ &kO_48, &kO_49, nullptr, nullptr, nullptr, nullptr, nullptr, &kO_4F,
    /* 0x50 */ &kO_50, &kO_51, nullptr, nullptr, nullptr, &kO_55, nullptr, &kO_57,
    /* 0x58 */ nullptr, nullptr, nullptr, &kO_5B, nullptr, nullptr, nullptr, &kO_5F,
    /* 0x60 */ nullptr, &kO_61, &kO_62, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0x68 */ &kO_68, nullptr, &kO_6A, nullptr, nullptr, &kO_6D, &kO_6E, nullptr,
    /* 0x70 */ &kO_70, nullptr, &kO_72, &kO_73, nullptr, &kO_75, nullptr, &kO_77,
    /* 0x78 */ &kO_78, &kO_79, &kO_7A, nullptr, &kO_7C, &kO_7D, nullptr, nullptr,
    /* 0x80 */ nullptr, nullptr, nullptr, nullptr, &kO_84, &kO_85, nullptr, nullptr,
    /* 0x88 */ nullptr, &kO_89, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0x90 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0x98 */ &kO_98, &kO_99, &kO_9A, nullptr, &kO_9C, nullptr, nullptr, nullptr,
    /* 0xA0 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xA8 */ nullptr, nullptr, nullptr, nullptr, &kO_AC, nullptr, nullptr, nullptr,
    /* 0xB0 */ nullptr, nullptr, nullptr, nullptr, nullptr, &kO_B5, nullptr, nullptr,
    /* 0xB8 */ nullptr, &kO_B9, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xC0 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xC8 */ nullptr, nullptr, nullptr, nullptr, &kO_CC, nullptr, nullptr, &kO_CF,
    /* 0xD0 */ nullptr, nullptr, nullptr, nullptr, nullptr, &kO_D5, nullptr, nullptr,
    /* 0xD8 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xE0 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xE8 */ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 0xF0 */ nullptr, nullptr, &kO_F2, nullptr, nullptr, nullptr, &kO_F6, nullptr,
    /* 0xF8 */ nullptr, &kO_F9, nullptr, nullptr, nullptr, &kO_FD, nullptr, nullptr,
};

} // namespace

const OpcodeInfo* findOpcode(std::uint8_t opcode, Direction dir) {
  const OpcodeInfo* hit = (dir == Direction::Out) ? kOutTable[opcode] : kInTable[opcode];
  if (hit != nullptr) return hit;
  // Istenen yonde kayit yoksa diger yone bak.
  return (dir == Direction::Out) ? kInTable[opcode] : kOutTable[opcode];
}

// Ad once alim, sonra giden tablosundan cozulur; giden opcode'lar da ad alir.
const char* opcodeName(std::uint8_t opcode) {
  if (const OpcodeInfo* e = kInTable[opcode]) return e->name;
  if (const OpcodeInfo* e = kOutTable[opcode]) return e->name;
  return "UNKNOWN";
}

bool isKnownOpcode(std::uint8_t opcode) {
  return kInTable[opcode] != nullptr || kOutTable[opcode] != nullptr;
}

// CELISKI KURALI: bir opcode iki yonde de kayitliysa Direction::Out doner.
// Gerekce: ayni numara iki yonde farkli govde tasir; giden govde istemci
// tarafindan uretildigi icin alan yerlesimi daha kesin bilinir. Yalniz bir
// yonde kayit varsa o yon doner; hic kayit yoksa varsayilan In'dir.
Direction opcodeDirection(std::uint8_t opcode) {
  if (kOutTable[opcode] != nullptr) return Direction::Out;
  if (const OpcodeInfo* e = kInTable[opcode]) return e->dir;
  return Direction::In;
}

} // namespace ko
