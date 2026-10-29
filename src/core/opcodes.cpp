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
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U16, "f3" },
    { 5, FieldType::U8, "f4" },
};
constexpr FieldSpec kF_02[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U16, "f3" },
    { 5, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_03[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U8, "f3" },
    { 7, FieldType::U8, "f4" },
    { 8, FieldType::U16, "f5" },
    { 10, FieldType::U16, "f6" },
    { 12, FieldType::U16, "f7" },
    { 14, FieldType::U16, "f8" },
    { 16, FieldType::U16, "f9" },
    { 18, FieldType::U16, "f10" },
};
constexpr FieldSpec kF_04[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U64, "f3" },
    { 18, FieldType::U8, "f4" },
    { 19, FieldType::Str, "f5" },
};
constexpr FieldSpec kF_05[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U16, "f2" },
    { 7, FieldType::U16, "f3" },
    { 9, FieldType::U16, "f4" },
    { 11, FieldType::U8, "f5" },
};
constexpr FieldSpec kF_06[] = {
    { 1, FieldType::U32, "obj_id" },
    { 5, FieldType::Coord, "f2" },
    { 7, FieldType::Coord, "f3" },
    { 9, FieldType::Coord, "f4" },
    { 11, FieldType::Coord, "f5" },
    { 13, FieldType::U8, "dir" },
};
constexpr FieldSpec kF_07[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_08[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U32, "f4" },
};
constexpr FieldSpec kF_09[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U16, "f2" },
};
constexpr FieldSpec kF_0A[] = {
    { 1, FieldType::U32, "npc_id" },
    { 5, FieldType::U16, "shape_id" },
    { 7, FieldType::U8, "kind" },
    { 8, FieldType::U16, "uid" },
    { 10, FieldType::U32, "resource_id" },
    { 14, FieldType::U8, "status" },
    { 15, FieldType::U32, "f7" },
    { 19, FieldType::U16, "f8" },
    { 21, FieldType::U32, "f9" },
    { 25, FieldType::U32, "f10" },
    { 29, FieldType::U8, "f11" },
    { 30, FieldType::Str, "name" },
};
constexpr FieldSpec kF_0B[] = {
    { 1, FieldType::U8, "obj_id" },
    { 2, FieldType::U32, "obj_id_hi" },
    { 6, FieldType::Coord, "f3" },
    { 8, FieldType::Coord, "f4" },
    { 10, FieldType::Coord, "f5" },
    { 12, FieldType::Coord, "dir" },
};
constexpr FieldSpec kF_0C[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_0E[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U8, "f2" },
    { 6, FieldType::Str, "f3" },
};
constexpr FieldSpec kF_10[] = {
    { 1, FieldType::U8, "chat_type" },
    { 2, FieldType::U64, "sender_id" },
    { 10, FieldType::U64, "f3" },
    { 18, FieldType::U8, "f4" },
    { 19, FieldType::U16, "f5" },
    { 21, FieldType::U16, "f6" },
    { 23, FieldType::U16, "f7" },
    { 25, FieldType::U16, "f8" },
    { 27, FieldType::U16, "f9" },
    { 29, FieldType::U16, "f10" },
    { 31, FieldType::U8, "f11" },
    { 32, FieldType::U8, "f12" },
    { 33, FieldType::U8, "f13" },
    { 34, FieldType::U8, "f14" },
};
constexpr FieldSpec kF_11[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U32, "f2" },
};
constexpr FieldSpec kF_12[] = {
    { 1, FieldType::Coord, "f1" },
    { 3, FieldType::Coord, "f2" },
    { 5, FieldType::U16, "dir" },
};
constexpr FieldSpec kF_14[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
};
constexpr FieldSpec kF_15[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U32, "f3" },
};
constexpr FieldSpec kF_16[] = {
    { 1, FieldType::U16, "f1" },
};
constexpr FieldSpec kF_17[] = {
    { 1, FieldType::U16, "hp" },
    { 3, FieldType::U16, "max_hp" },
    { 5, FieldType::U32, "delta" },
};
constexpr FieldSpec kF_18[] = {
    { 1, FieldType::U16, "msp" },
    { 3, FieldType::U16, "max_msp" },
};
constexpr FieldSpec kF_19[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_1A[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U32, "f3" },
    { 14, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_1B[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U8, "f2" },
    { 6, FieldType::U8, "f3" },
    { 7, FieldType::U16, "f4" },
    { 9, FieldType::U8, "f5" },
    { 10, FieldType::U64, "f6" },
    { 18, FieldType::U16, "f7" },
    { 20, FieldType::U16, "f8" },
    { 22, FieldType::U16, "f9" },
    { 24, FieldType::U16, "f10" },
    { 26, FieldType::U32, "f11" },
    { 30, FieldType::U32, "f12" },
};
constexpr FieldSpec kF_1C[] = {
    { 1, FieldType::U16, "f1" },
};
constexpr FieldSpec kF_1D[] = {
    { 1, FieldType::U16, "f1" },
};
constexpr FieldSpec kF_1F[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U8, "f4" },
    { 5, FieldType::U8, "f5" },
    { 6, FieldType::U8, "f6" },
    { 7, FieldType::U16, "f7" },
    { 9, FieldType::U8, "f8" },
};
constexpr FieldSpec kF_20[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U16, "f3" },
};
constexpr FieldSpec kF_21[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U32, "f4" },
    { 11, FieldType::U8, "f5" },
};
constexpr FieldSpec kF_22[] = {
    { 1, FieldType::U32, "target_id" },
    { 5, FieldType::U8, "f2" },
    { 6, FieldType::U32, "hp" },
    { 10, FieldType::U32, "max_hp" },
    { 14, FieldType::U8, "f5" },
};
constexpr FieldSpec kF_23[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U32, "f2" },
    { 9, FieldType::U8, "f3" },
};
constexpr FieldSpec kF_24[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U8, "f2" },
    { 6, FieldType::U32, "f3" },
    { 10, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_25[] = {
    { 1, FieldType::U32, "f1" },
};
constexpr FieldSpec kF_26[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U8, "f3" },
};
constexpr FieldSpec kF_28[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::Coord, "f2" },
    { 4, FieldType::Coord, "f3" },
    { 6, FieldType::Coord, "f4" },
    { 8, FieldType::Coord, "f5" },
    { 10, FieldType::U32, "f6" },
    { 14, FieldType::U8, "f7" },
};
constexpr FieldSpec kF_29[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U16, "f2" },
    { 7, FieldType::U8, "f3" },
};
constexpr FieldSpec kF_2A[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U32, "f3" },
    { 10, FieldType::U32, "f4" },
    { 14, FieldType::U32, "f5" },
};
constexpr FieldSpec kF_2D[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U8, "f2" },
    { 6, FieldType::U32, "f3" },
    { 10, FieldType::U16, "f4" },
    { 12, FieldType::U8, "f5" },
    { 13, FieldType::U8, "f6" },
};
constexpr FieldSpec kF_2E[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_2F[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::Str, "f2" },
};
constexpr FieldSpec kF_30[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U8, "f3" },
    { 7, FieldType::U8, "f4" },
    { 8, FieldType::U32, "f5" },
    { 12, FieldType::U64, "f6" },
    { 20, FieldType::U32, "f7" },
    { 24, FieldType::U8, "f8" },
    { 25, FieldType::U8, "f9" },
    { 26, FieldType::U32, "f10" },
    { 30, FieldType::U16, "f11" },
    { 32, FieldType::U16, "f12" },
    { 34, FieldType::U8, "f13" },
    { 35, FieldType::U32, "f14" },
    { 39, FieldType::U8, "f15" },
};
constexpr FieldSpec kF_31[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_33[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U64, "f3" },
    { 18, FieldType::U8, "f4" },
    { 19, FieldType::U32, "f5" },
    { 23, FieldType::U8, "f6" },
};
constexpr FieldSpec kF_34[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
};
constexpr FieldSpec kF_35[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U32, "f3" },
    { 8, FieldType::U32, "f4" },
    { 12, FieldType::U32, "f5" },
    { 16, FieldType::Str, "f6" },
};
constexpr FieldSpec kF_36[] = {
    { 1, FieldType::U16, "f1" },
};
constexpr FieldSpec kF_38[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
};
constexpr FieldSpec kF_3A[] = {
    { 1, FieldType::U32, "f1" },
};
constexpr FieldSpec kF_3D[] = {
    { 1, FieldType::U16, "f1" },
    { 3, FieldType::U8, "f2" },
    { 4, FieldType::U8, "f3" },
    { 5, FieldType::U32, "f4" },
    { 9, FieldType::U32, "f5" },
    { 13, FieldType::U8, "f6" },
    { 14, FieldType::U16, "f7" },
    { 16, FieldType::U32, "f8" },
    { 20, FieldType::U32, "f9" },
};
constexpr FieldSpec kF_3E[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U16, "f3" },
    { 6, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_3F[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_40[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U64, "f3" },
    { 18, FieldType::U16, "f4" },
    { 20, FieldType::U16, "f5" },
    { 22, FieldType::Str, "f6" },
};
constexpr FieldSpec kF_44[] = {
    { 1, FieldType::U16, "f1" },
    { 3, FieldType::U64, "f2" },
    { 11, FieldType::U64, "f3" },
    { 19, FieldType::U16, "f4" },
    { 21, FieldType::U16, "f5" },
};
constexpr FieldSpec kF_45[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U8, "f4" },
    { 5, FieldType::U8, "f5" },
    { 6, FieldType::U8, "f6" },
    { 7, FieldType::U8, "f7" },
    { 8, FieldType::U8, "f8" },
};
constexpr FieldSpec kF_46[] = {
    { 1, FieldType::Str, "f1" },
    { 3, FieldType::U8, "f2" },
    { 4, FieldType::U16, "f3" },
    { 6, FieldType::U8, "f4" },
};
constexpr FieldSpec kF_49[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::Str, "f3" },
};
constexpr FieldSpec kF_4A[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U32, "f3" },
};
constexpr FieldSpec kF_4B[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U16, "f3" },
    { 6, FieldType::U16, "f4" },
    { 8, FieldType::Str, "f5" },
};
constexpr FieldSpec kF_4E[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U32, "f3" },
    { 8, FieldType::U8, "f4" },
    { 9, FieldType::U8, "f5" },
    { 10, FieldType::Str, "f6" },
};
constexpr FieldSpec kF_4F[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_50[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U8, "f4" },
    { 5, FieldType::U8, "f5" },
};
constexpr FieldSpec kF_53[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U16, "f4" },
    { 9, FieldType::U8, "f5" },
    { 10, FieldType::U8, "f6" },
};
constexpr FieldSpec kF_54[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_55[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U8, "f2" },
    { 6, FieldType::U32, "f3" },
};
constexpr FieldSpec kF_57[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_58[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U8, "f3" },
};
constexpr FieldSpec kF_59[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_5A[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_5B[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_5E[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U8, "f4" },
    { 5, FieldType::U16, "f5" },
    { 7, FieldType::U8, "f6" },
    { 8, FieldType::U8, "f7" },
    { 9, FieldType::U8, "f8" },
    { 10, FieldType::U32, "f9" },
};
constexpr FieldSpec kF_5F[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_60[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
};
constexpr FieldSpec kF_61[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_63[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U8, "f3" },
};
constexpr FieldSpec kF_64[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U16, "f3" },
    { 5, FieldType::U16, "f4" },
    { 7, FieldType::U32, "f5" },
    { 11, FieldType::U32, "f6" },
};
constexpr FieldSpec kF_65[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_66[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U32, "f2" },
};
constexpr FieldSpec kF_68[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_69[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U16, "f3" },
    { 8, FieldType::U32, "f4" },
    { 12, FieldType::U32, "f5" },
    { 16, FieldType::U32, "f6" },
    { 20, FieldType::U32, "f7" },
    { 24, FieldType::U32, "f8" },
    { 28, FieldType::U32, "f9" },
    { 32, FieldType::U32, "f10" },
    { 36, FieldType::U32, "f11" },
    { 40, FieldType::U8, "f12" },
    { 41, FieldType::U16, "f13" },
    { 43, FieldType::U32, "f14" },
    { 47, FieldType::U8, "f15" },
    { 48, FieldType::U8, "f16" },
};
constexpr FieldSpec kF_6A[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_6C[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U16, "f2" },
    { 7, FieldType::U32, "f3" },
    { 11, FieldType::U8, "f4" },
    { 12, FieldType::Str, "f5" },
};
constexpr FieldSpec kF_6D[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_6E[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_70[] = {
    { 1, FieldType::U16, "f1" },
};
constexpr FieldSpec kF_71[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U16, "f4" },
    { 6, FieldType::U8, "f5" },
};
constexpr FieldSpec kF_73[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
};
constexpr FieldSpec kF_74[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U16, "f2" },
    { 7, FieldType::U32, "f3" },
    { 11, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_75[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_76[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U32, "f4" },
    { 11, FieldType::U16, "f5" },
    { 13, FieldType::U32, "f6" },
    { 17, FieldType::U8, "f7" },
};
constexpr FieldSpec kF_78[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::Str, "f2" },
};
constexpr FieldSpec kF_79[] = {
    { 1, FieldType::U16, "f1" },
    { 3, FieldType::U32, "f2" },
};
constexpr FieldSpec kF_7A[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_7C[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::Str, "f2" },
};
constexpr FieldSpec kF_7D[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U64, "f3" },
    { 18, FieldType::U8, "f4" },
    { 19, FieldType::U32, "f5" },
    { 23, FieldType::U8, "f6" },
    { 24, FieldType::Str, "f7" },
};
constexpr FieldSpec kF_80[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_81[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U8, "f4" },
    { 8, FieldType::U8, "f5" },
    { 9, FieldType::U32, "f6" },
    { 13, FieldType::U32, "f7" },
    { 17, FieldType::U8, "f8" },
    { 18, FieldType::U8, "f9" },
    { 19, FieldType::U8, "f10" },
    { 20, FieldType::U16, "f11" },
    { 22, FieldType::U16, "f12" },
    { 24, FieldType::U16, "f13" },
    { 26, FieldType::U16, "f14" },
    { 28, FieldType::Str, "f15" },
};
constexpr FieldSpec kF_82[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_84[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U64, "f3" },
    { 18, FieldType::Coord, "f4" },
};
constexpr FieldSpec kF_85[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U16, "f3" },
    { 5, FieldType::U32, "f4" },
    { 9, FieldType::U8, "f5" },
    { 10, FieldType::U8, "f6" },
};
constexpr FieldSpec kF_86[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_87[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
};
constexpr FieldSpec kF_88[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_8B[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_8D[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U8, "f3" },
    { 7, FieldType::U8, "f4" },
    { 8, FieldType::U8, "f5" },
    { 9, FieldType::U8, "f6" },
    { 10, FieldType::U32, "f7" },
};
constexpr FieldSpec kF_90[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U32, "f3" },
};
constexpr FieldSpec kF_91[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_92[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U64, "f3" },
    { 11, FieldType::U8, "f4" },
    { 12, FieldType::U32, "f5" },
    { 16, FieldType::U16, "f6" },
    { 18, FieldType::U16, "f7" },
    { 20, FieldType::U8, "f8" },
    { 21, FieldType::U32, "f9" },
};
constexpr FieldSpec kF_95[] = {
    { 1, FieldType::U32, "f1" },
    { 5, FieldType::U16, "f2" },
    { 7, FieldType::U16, "f3" },
    { 9, FieldType::U16, "f4" },
    { 11, FieldType::Str, "f5" },
};
constexpr FieldSpec kF_97[] = {
    { 1, FieldType::U16, "f1" },
    { 3, FieldType::U16, "f2" },
};
constexpr FieldSpec kF_98[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_99[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U16, "f3" },
    { 5, FieldType::U16, "f4" },
    { 7, FieldType::U16, "f5" },
    { 9, FieldType::U8, "f6" },
    { 10, FieldType::U32, "f7" },
};
constexpr FieldSpec kF_9A[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U8, "f4" },
    { 5, FieldType::U16, "f5" },
    { 7, FieldType::U16, "f6" },
};
constexpr FieldSpec kF_9B[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_9C[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_A0[] = {
    { 1, FieldType::U16, "f1" },
    { 3, FieldType::Str, "f2" },
};
constexpr FieldSpec kF_A5[] = {
    { 1, FieldType::U32, "f1" },
};
constexpr FieldSpec kF_A9[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U16, "f3" },
    { 8, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_AC[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U32, "f4" },
};
constexpr FieldSpec kF_B5[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_B6[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
    { 4, FieldType::U8, "f4" },
    { 5, FieldType::U8, "f5" },
    { 6, FieldType::U8, "f6" },
};
constexpr FieldSpec kF_B7[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_B8[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_B9[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_BD[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_C0[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_C2[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_C3[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U64, "f2" },
    { 10, FieldType::U8, "f3" },
    { 11, FieldType::U64, "f4" },
    { 19, FieldType::U8, "f5" },
};
constexpr FieldSpec kF_C5[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::U16, "f3" },
};
constexpr FieldSpec kF_C7[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U16, "f4" },
    { 9, FieldType::U8, "f5" },
    { 10, FieldType::U8, "f6" },
    { 11, FieldType::U32, "f7" },
    { 15, FieldType::U16, "f8" },
};
constexpr FieldSpec kF_C8[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_CB[] = {
    { 1, FieldType::U32, "f1" },
};
constexpr FieldSpec kF_CC[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_CE[] = {
    { 1, FieldType::U16, "f1" },
};
constexpr FieldSpec kF_CF[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U8, "f3" },
};
constexpr FieldSpec kF_D0[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_D1[] = {
    { 1, FieldType::U8, "f1" },
};
constexpr FieldSpec kF_D3[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
    { 3, FieldType::U32, "f3" },
    { 7, FieldType::U32, "f4" },
    { 11, FieldType::U32, "f5" },
    { 15, FieldType::U32, "f6" },
};
constexpr FieldSpec kF_D5[] = {
    { 1, FieldType::U16, "f1" },
    { 3, FieldType::U8, "f2" },
    { 4, FieldType::U8, "f3" },
    { 5, FieldType::U16, "f4" },
    { 7, FieldType::U16, "f5" },
    { 9, FieldType::U8, "f6" },
    { 10, FieldType::U16, "f7" },
    { 12, FieldType::U16, "f8" },
    { 14, FieldType::U8, "f9" },
    { 15, FieldType::U8, "f10" },
    { 16, FieldType::U32, "f11" },
    { 20, FieldType::U32, "f12" },
};
constexpr FieldSpec kF_D6[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U8, "f2" },
};
constexpr FieldSpec kF_D7[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U32, "f2" },
    { 6, FieldType::U32, "f3" },
    { 10, FieldType::U16, "f4" },
};
constexpr FieldSpec kF_D9[] = {
    { 1, FieldType::U8, "f1" },
    { 2, FieldType::U16, "f2" },
    { 4, FieldType::Str, "f3" },
};

constexpr OpcodeInfo kI_01 = { 0x01, "WIZ_LOGIN_UNVERIFIED", Direction::In, kF_01, 4, true, false, true, true };
constexpr OpcodeInfo kI_02 = { 0x02, "WIZ_NEW_CHAR_UNVERIFIED", Direction::In, kF_02, 4, true, true, false, false };
constexpr OpcodeInfo kI_03 = { 0x03, "WIZ_DEL_CHAR_UNVERIFIED", Direction::In, kF_03, 10, true, true, false, false };
constexpr OpcodeInfo kI_04 = { 0x04, "WIZ_SEL_CHAR_UNVERIFIED", Direction::In, kF_04, 5, true, true, true, false };
constexpr OpcodeInfo kI_05 = { 0x05, "WIZ_SEL_NATION_UNVERIFIED", Direction::In, kF_05, 5, true, true, false, false };
constexpr OpcodeInfo kI_06 = { 0x06, "WIZ_MOVE", Direction::In, kF_06, 6, false, false, false, false };
constexpr OpcodeInfo kI_07 = { 0x07, "WIZ_USER_INOUT_UNVERIFIED", Direction::In, kF_07, 1, true, true, false, false };
constexpr OpcodeInfo kI_08 = { 0x08, "WIZ_ATTACK_UNVERIFIED", Direction::In, kF_08, 4, true, false, false, false };
constexpr OpcodeInfo kI_09 = { 0x09, "WIZ_ROTATE_UNVERIFIED", Direction::In, kF_09, 2, true, true, false, false };
constexpr OpcodeInfo kI_0A = { 0x0A, "WIZ_NPC_INOUT", Direction::In, kF_0A, 12, false, true, false, true };
constexpr OpcodeInfo kI_0B = { 0x0B, "WIZ_NPC_MOVE", Direction::In, kF_0B, 6, false, false, false, false };
constexpr OpcodeInfo kI_0C = { 0x0C, "WIZ_ALLCHAR_INFO_REQ_UNVERIFIED", Direction::In, kF_0C, 1, true, false, false, false };
constexpr OpcodeInfo kI_0D = { 0x0D, "WIZ_GAMESTART_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_0E = { 0x0E, "WIZ_MYINFO", Direction::In, kF_0E, 3, false, true, false, false };
constexpr OpcodeInfo kI_10 = { 0x10, "WIZ_CHAT", Direction::In, kF_10, 14, false, true, false, false };
constexpr OpcodeInfo kI_11 = { 0x11, "WIZ_DEAD_UNVERIFIED", Direction::In, kF_11, 2, true, true, false, false };
constexpr OpcodeInfo kI_12 = { 0x12, "WIZ_REGENE_UNVERIFIED", Direction::In, kF_12, 3, true, true, false, false };
constexpr OpcodeInfo kI_14 = { 0x14, "WIZ_WEATHER_UNVERIFIED", Direction::In, kF_14, 2, true, false, false, false };
constexpr OpcodeInfo kI_15 = { 0x15, "WIZ_REGIONCHANGE_UNVERIFIED", Direction::In, kF_15, 3, true, true, false, false };
constexpr OpcodeInfo kI_16 = { 0x16, "WIZ_REQ_USERIN_UNVERIFIED", Direction::In, kF_16, 1, true, false, false, false };
constexpr OpcodeInfo kI_17 = { 0x17, "WIZ_HP_CHANGE_UNVERIFIED", Direction::In, kF_17, 3, true, true, false, false };
constexpr OpcodeInfo kI_18 = { 0x18, "WIZ_MSP_CHANGE_UNVERIFIED", Direction::In, kF_18, 2, true, true, false, false };
constexpr OpcodeInfo kI_19 = { 0x19, "WIZ_ITEM_LOG_UNVERIFIED", Direction::In, kF_19, 1, true, false, false, true };
constexpr OpcodeInfo kI_1A = { 0x1A, "WIZ_EXP_CHANGE_UNVERIFIED", Direction::In, kF_1A, 4, true, false, false, false };
constexpr OpcodeInfo kI_1B = { 0x1B, "WIZ_LEVEL_CHANGE", Direction::In, kF_1B, 12, false, true, false, false };
constexpr OpcodeInfo kI_1C = { 0x1C, "WIZ_NPC_REGION_UNVERIFIED", Direction::In, kF_1C, 1, true, true, false, false };
constexpr OpcodeInfo kI_1D = { 0x1D, "WIZ_REQ_NPCIN_UNVERIFIED", Direction::In, kF_1D, 1, true, false, false, false };
constexpr OpcodeInfo kI_1E = { 0x1E, "WIZ_WARP_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_1F = { 0x1F, "WIZ_ITEM_MOVE_UNVERIFIED", Direction::In, kF_1F, 8, true, false, false, false };
constexpr OpcodeInfo kI_20 = { 0x20, "WIZ_NPC_EVENT_UNVERIFIED", Direction::In, kF_20, 3, true, true, false, false };
constexpr OpcodeInfo kI_21 = { 0x21, "WIZ_ITEM_TRADE_UNVERIFIED", Direction::In, kF_21, 5, true, false, false, false };
constexpr OpcodeInfo kI_22 = { 0x22, "WIZ_TARGET_HP", Direction::In, kF_22, 5, false, true, false, false };
constexpr OpcodeInfo kI_23 = { 0x23, "WIZ_ITEM_DROP_UNVERIFIED", Direction::In, kF_23, 3, true, false, false, false };
constexpr OpcodeInfo kI_24 = { 0x24, "WIZ_BUNDLE_OPEN_REQ_UNVERIFIED", Direction::In, kF_24, 4, true, false, false, false };
constexpr OpcodeInfo kI_25 = { 0x25, "WIZ_TRADE_NPC_UNVERIFIED", Direction::In, kF_25, 1, true, true, false, false };
constexpr OpcodeInfo kI_26 = { 0x26, "WIZ_ITEM_GET_UNVERIFIED", Direction::In, kF_26, 3, true, true, false, false };
constexpr OpcodeInfo kI_27 = { 0x27, "WIZ_ZONE_CHANGE_UNVERIFIED", Direction::In, nullptr, 0, true, true, false, false };
constexpr OpcodeInfo kI_28 = { 0x28, "WIZ_POINT_CHANGE_UNVERIFIED", Direction::In, kF_28, 7, true, true, false, false };
constexpr OpcodeInfo kI_29 = { 0x29, "WIZ_STATE_CHANGE_UNVERIFIED", Direction::In, kF_29, 3, true, true, false, false };
constexpr OpcodeInfo kI_2A = { 0x2A, "WIZ_LOYALTY_CHANGE_UNVERIFIED", Direction::In, kF_2A, 5, true, true, false, false };
constexpr OpcodeInfo kI_2B = { 0x2B, "WIZ_VERSION_CHECK_UNVERIFIED", Direction::In, nullptr, 0, true, true, true, false };
constexpr OpcodeInfo kI_2D = { 0x2D, "WIZ_USERLOOK_CHANGE", Direction::In, kF_2D, 6, false, true, false, false };
constexpr OpcodeInfo kI_2E = { 0x2E, "WIZ_NOTICE_UNVERIFIED", Direction::In, kF_2E, 1, true, false, false, false };
constexpr OpcodeInfo kI_2F = { 0x2F, "WIZ_PARTY_UNVERIFIED", Direction::In, kF_2F, 2, true, true, false, false };
constexpr OpcodeInfo kI_30 = { 0x30, "WIZ_EXCHANGE_UNVERIFIED", Direction::In, kF_30, 15, true, false, false, false };
constexpr OpcodeInfo kI_31 = { 0x31, "WIZ_MAGIC_PROCESS_UNVERIFIED", Direction::In, kF_31, 1, true, true, false, false };
constexpr OpcodeInfo kI_33 = { 0x33, "WIZ_OBJECT_EVENT", Direction::In, kF_33, 6, false, false, false, false };
constexpr OpcodeInfo kI_34 = { 0x34, "WIZ_CLASS_CHANGE_UNVERIFIED", Direction::In, kF_34, 3, true, false, false, false };
constexpr OpcodeInfo kI_35 = { 0x35, "WIZ_CHAT_TARGET_UNVERIFIED", Direction::In, kF_35, 6, true, true, false, false };
constexpr OpcodeInfo kI_36 = { 0x36, "WIZ_CONCURRENTUSER_UNVERIFIED", Direction::In, kF_36, 1, true, false, false, false };
constexpr OpcodeInfo kI_38 = { 0x38, "WIZ_DURATION_UNVERIFIED", Direction::In, kF_38, 2, true, false, false, false };
constexpr OpcodeInfo kI_3A = { 0x3A, "WIZ_REPAIR_NPC_UNVERIFIED", Direction::In, kF_3A, 1, true, true, false, false };
constexpr OpcodeInfo kI_3B = { 0x3B, "WIZ_ITEM_REPAIR_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_3C = { 0x3C, "WIZ_KNIGHTS_PROCESS_UNVERIFIED", Direction::In, nullptr, 0, true, true, false, false };
constexpr OpcodeInfo kI_3D = { 0x3D, "WIZ_ITEM_COUNT_CHANGE_UNVERIFIED", Direction::In, kF_3D, 9, true, true, false, false };
constexpr OpcodeInfo kI_3E = { 0x3E, "WIZ_KNIGHTS_LIST_UNVERIFIED", Direction::In, kF_3E, 4, true, true, false, false };
constexpr OpcodeInfo kI_3F = { 0x3F, "WIZ_ITEM_REMOVE_UNVERIFIED", Direction::In, kF_3F, 2, true, false, false, false };
constexpr OpcodeInfo kI_40 = { 0x40, "WIZ_OPERATOR", Direction::In, kF_40, 6, false, true, false, false };
constexpr OpcodeInfo kI_42 = { 0x42, "WIZ_COMPRESS_PACKET", Direction::In, nullptr, 0, false, false, false, false };
constexpr OpcodeInfo kI_44 = { 0x44, "WIZ_CONTINOUS_PACKET_UNVERIFIED", Direction::In, kF_44, 5, true, false, false, false };
constexpr OpcodeInfo kI_45 = { 0x45, "WIZ_WAREHOUSE_UNVERIFIED", Direction::In, kF_45, 8, true, false, false, false };
constexpr OpcodeInfo kI_46 = { 0x46, "WIZ_SERVER_CHANGE_UNVERIFIED", Direction::In, kF_46, 4, true, true, true, false };
constexpr OpcodeInfo kI_49 = { 0x49, "WIZ_FRIEND_PROCESS_UNVERIFIED", Direction::In, kF_49, 3, true, true, false, false };
constexpr OpcodeInfo kI_4A = { 0x4A, "WIZ_GOLD_CHANGE_UNVERIFIED", Direction::In, kF_4A, 3, true, true, false, false };
constexpr OpcodeInfo kI_4B = { 0x4B, "WIZ_WARP_LIST_UNVERIFIED", Direction::In, kF_4B, 5, true, true, false, false };
constexpr OpcodeInfo kI_4E = { 0x4E, "WIZ_CORPSE_UNVERIFIED", Direction::In, kF_4E, 6, true, true, false, false };
constexpr OpcodeInfo kI_4F = { 0x4F, "WIZ_PARTY_BBS_UNVERIFIED", Direction::In, kF_4F, 1, true, false, false, false };
constexpr OpcodeInfo kI_50 = { 0x50, "WIZ_MARKET_BBS_UNVERIFIED", Direction::In, kF_50, 5, true, true, false, false };
constexpr OpcodeInfo kI_53 = { 0x53, "WIZ_MAP_EVENT_UNVERIFIED", Direction::In, kF_53, 6, true, false, false, false };
constexpr OpcodeInfo kI_54 = { 0x54, "WIZ_WEIGHT_CHANGE_UNVERIFIED", Direction::In, kF_54, 2, true, true, false, false };
constexpr OpcodeInfo kI_55 = { 0x55, "WIZ_SELECT_MSG_UNVERIFIED", Direction::In, kF_55, 3, true, true, false, false };
constexpr OpcodeInfo kI_57 = { 0x57, "WIZ_BATTLE_EVENT_UNVERIFIED", Direction::In, kF_57, 1, true, false, false, false };
constexpr OpcodeInfo kI_58 = { 0x58, "WIZ_AUTHORITY_CHANGE_UNVERIFIED", Direction::In, kF_58, 3, true, false, false, false };
constexpr OpcodeInfo kI_59 = { 0x59, "WIZ_EDIT_BOX_UNVERIFIED", Direction::In, kF_59, 1, true, false, false, false };
constexpr OpcodeInfo kI_5A = { 0x5A, "WIZ_SANTA_UNVERIFIED", Direction::In, kF_5A, 1, true, false, false, false };
constexpr OpcodeInfo kI_5B = { 0x5B, "WIZ_ITEM_UPGRADE_UNVERIFIED", Direction::In, kF_5B, 1, true, false, false, false };
constexpr OpcodeInfo kI_5D = { 0x5D, "WIZ_PACKET2_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_5E = { 0x5E, "WIZ_ZONEABILITY_UNVERIFIED", Direction::In, kF_5E, 9, true, false, false, false };
constexpr OpcodeInfo kI_5F = { 0x5F, "WIZ_EVENT_UNVERIFIED", Direction::In, kF_5F, 2, true, true, false, false };
constexpr OpcodeInfo kI_60 = { 0x60, "WIZ_STEALTH_UNVERIFIED", Direction::In, kF_60, 2, true, false, false, false };
constexpr OpcodeInfo kI_61 = { 0x61, "WIZ_ROOM_PACKETPROCESS_UNVERIFIED", Direction::In, kF_61, 1, true, false, false, false };
constexpr OpcodeInfo kI_63 = { 0x63, "WIZ_PACKET3_UNVERIFIED", Direction::In, kF_63, 3, true, false, false, false };
constexpr OpcodeInfo kI_64 = { 0x64, "WIZ_QUEST", Direction::In, kF_64, 6, false, true, false, false };
constexpr OpcodeInfo kI_65 = { 0x65, "WIZ_PACKET4_UNVERIFIED", Direction::In, kF_65, 1, true, false, false, false };
constexpr OpcodeInfo kI_66 = { 0x66, "WIZ_KISS_UNVERIFIED", Direction::In, kF_66, 2, true, false, false, false };
constexpr OpcodeInfo kI_68 = { 0x68, "WIZ_MERCHANT", Direction::In, kF_68, 2, false, true, false, false };
constexpr OpcodeInfo kI_69 = { 0x69, "WIZ_MERCHANT_INOUT_UNVERIFIED", Direction::In, kF_69, 16, true, false, false, false };
constexpr OpcodeInfo kI_6A = { 0x6A, "WIZ_SHOPPING_MALL_UNVERIFIED", Direction::In, kF_6A, 1, true, false, false, false };
constexpr OpcodeInfo kI_6B = { 0x6B, "WIZ_SERVER_INDEX_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_6C = { 0x6C, "WIZ_EFFECT_UNVERIFIED", Direction::In, kF_6C, 5, true, true, false, false };
constexpr OpcodeInfo kI_6D = { 0x6D, "WIZ_SIEGE_UNVERIFIED", Direction::In, kF_6D, 2, true, true, false, false };
constexpr OpcodeInfo kI_6E = { 0x6E, "WIZ_NAME_CHANGE_UNVERIFIED", Direction::In, kF_6E, 1, true, true, false, false };
constexpr OpcodeInfo kI_70 = { 0x70, "WIZ_CAPE_UNVERIFIED", Direction::In, kF_70, 1, true, false, false, false };
constexpr OpcodeInfo kI_71 = { 0x71, "WIZ_PREMIUM", Direction::In, kF_71, 5, false, true, false, false };
constexpr OpcodeInfo kI_72 = { 0x72, "WIZ_HACKTOOL_UNVERIFIED", Direction::In, nullptr, 0, true, true, true, false };
constexpr OpcodeInfo kI_73 = { 0x73, "WIZ_RENTAL_UNVERIFIED", Direction::In, kF_73, 2, true, true, false, false };
constexpr OpcodeInfo kI_74 = { 0x74, "WIZ_PACKET5_UNVERIFIED", Direction::In, kF_74, 4, true, true, false, false };
constexpr OpcodeInfo kI_75 = { 0x75, "WIZ_CHALLENGE_UNVERIFIED", Direction::In, kF_75, 1, true, false, false, false };
constexpr OpcodeInfo kI_76 = { 0x76, "WIZ_PET_UNVERIFIED", Direction::In, kF_76, 7, true, false, false, false };
constexpr OpcodeInfo kI_78 = { 0x78, "WIZ_KING_UNVERIFIED", Direction::In, kF_78, 2, true, true, false, false };
constexpr OpcodeInfo kI_79 = { 0x79, "WIZ_SKILLDATA", Direction::In, kF_79, 2, false, true, false, false };
constexpr OpcodeInfo kI_7A = { 0x7A, "WIZ_PROGRAMCHECK_UNVERIFIED", Direction::In, kF_7A, 1, true, false, false, false };
constexpr OpcodeInfo kI_7B = { 0x7B, "WIZ_BIFROST_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_7C = { 0x7C, "WIZ_REPORT", Direction::In, kF_7C, 2, false, true, false, false };
constexpr OpcodeInfo kI_7D = { 0x7D, "WIZ_LOGOSSHOUT_UNVERIFIED", Direction::In, kF_7D, 7, true, true, false, false };
constexpr OpcodeInfo kI_80 = { 0x80, "WIZ_RANK_UNVERIFIED", Direction::In, kF_80, 1, true, false, false, false };
constexpr OpcodeInfo kI_81 = { 0x81, "WIZ_STORY_UNVERIFIED", Direction::In, kF_81, 15, true, true, false, false };
constexpr OpcodeInfo kI_82 = { 0x82, "WIZ_PACKET8_UNVERIFIED", Direction::In, kF_82, 2, true, true, false, false };
constexpr OpcodeInfo kI_83 = { 0x83, "WIZ_PACKET9_UNVERIFIED", Direction::In, nullptr, 0, true, true, false, false };
constexpr OpcodeInfo kI_84 = { 0x84, "WIZ_PACKET10_UNVERIFIED", Direction::In, kF_84, 4, true, true, false, false };
constexpr OpcodeInfo kI_85 = { 0x85, "WIZ_PACKET11_UNVERIFIED", Direction::In, kF_85, 6, true, true, false, false };
constexpr OpcodeInfo kI_86 = { 0x86, "WIZ_MINING_UNVERIFIED", Direction::In, kF_86, 2, true, true, false, false };
constexpr OpcodeInfo kI_87 = { 0x87, "WIZ_HELMET", Direction::In, kF_87, 3, false, false, false, false };
constexpr OpcodeInfo kI_88 = { 0x88, "WIZ_PVP_UNVERIFIED", Direction::In, kF_88, 1, true, false, false, false };
constexpr OpcodeInfo kI_89 = { 0x89, "WIZ_CHANGE_HAIR_UNVERIFIED", Direction::In, nullptr, 0, true, true, true, false };
constexpr OpcodeInfo kI_8B = { 0x8B, "WIZ_PACKET13_UNVERIFIED", Direction::In, kF_8B, 2, true, false, false, false };
constexpr OpcodeInfo kI_8D = { 0x8D, "WIZ_PACKET15_UNVERIFIED", Direction::In, kF_8D, 7, true, false, false, false };
constexpr OpcodeInfo kI_90 = { 0x90, "WIZ_DEATH_LIST_UNVERIFIED", Direction::In, kF_90, 3, true, false, false, false };
constexpr OpcodeInfo kI_91 = { 0x91, "WIZ_CLANPOINTS_BATTLE_UNVERIFIED", Direction::In, kF_91, 2, true, false, false, false };
constexpr OpcodeInfo kI_92 = { 0x92, "OP_92_UNVERIFIED", Direction::In, kF_92, 9, true, false, false, false };
constexpr OpcodeInfo kI_95 = { 0x95, "OP_95_UNVERIFIED", Direction::In, kF_95, 5, true, true, false, false };
constexpr OpcodeInfo kI_97 = { 0x97, "OP_97_UNVERIFIED", Direction::In, kF_97, 2, true, false, false, false };
constexpr OpcodeInfo kI_98 = { 0x98, "OP_98_UNVERIFIED", Direction::In, kF_98, 1, true, false, false, false };
constexpr OpcodeInfo kI_99 = { 0x99, "OP_99_UNVERIFIED", Direction::In, kF_99, 7, true, true, false, false };
constexpr OpcodeInfo kI_9A = { 0x9A, "OP_9A_UNVERIFIED", Direction::In, kF_9A, 6, true, true, false, false };
constexpr OpcodeInfo kI_9B = { 0x9B, "OP_9B_UNVERIFIED", Direction::In, kF_9B, 1, true, false, false, false };
constexpr OpcodeInfo kI_9C = { 0x9C, "OP_9C_UNVERIFIED", Direction::In, kF_9C, 1, true, false, false, false };
constexpr OpcodeInfo kI_9F = { 0x9F, "OP_9F_UNVERIFIED", Direction::In, nullptr, 0, true, true, true, false };
constexpr OpcodeInfo kI_A0 = { 0xA0, "WIZ_XINCODE", Direction::In, kF_A0, 2, false, true, true, false };
constexpr OpcodeInfo kI_A5 = { 0xA5, "OP_A5_UNVERIFIED", Direction::In, kF_A5, 1, true, false, false, false };
constexpr OpcodeInfo kI_A9 = { 0xA9, "OP_A9_UNVERIFIED", Direction::In, kF_A9, 4, true, true, false, false };
constexpr OpcodeInfo kI_AC = { 0xAC, "OP_AC_UNVERIFIED", Direction::In, kF_AC, 4, true, true, false, false };
constexpr OpcodeInfo kI_B4 = { 0xB4, "OP_B4_UNVERIFIED", Direction::In, nullptr, 0, true, false, false, false };
constexpr OpcodeInfo kI_B5 = { 0xB5, "OP_B5_UNVERIFIED", Direction::In, kF_B5, 2, true, true, false, false };
constexpr OpcodeInfo kI_B6 = { 0xB6, "OP_B6_UNVERIFIED", Direction::In, kF_B6, 6, true, true, false, false };
constexpr OpcodeInfo kI_B7 = { 0xB7, "OP_B7_UNVERIFIED", Direction::In, kF_B7, 1, true, false, false, false };
constexpr OpcodeInfo kI_B8 = { 0xB8, "OP_B8_UNVERIFIED", Direction::In, kF_B8, 2, true, true, false, false };
constexpr OpcodeInfo kI_B9 = { 0xB9, "OP_B9_UNVERIFIED", Direction::In, kF_B9, 2, true, true, false, false };
constexpr OpcodeInfo kI_BD = { 0xBD, "OP_BD_UNVERIFIED", Direction::In, kF_BD, 1, true, false, false, false };
constexpr OpcodeInfo kI_C0 = { 0xC0, "OP_C0_UNVERIFIED", Direction::In, kF_C0, 1, true, false, false, false };
constexpr OpcodeInfo kI_C2 = { 0xC2, "OP_C2_UNVERIFIED", Direction::In, kF_C2, 2, true, true, false, false };
constexpr OpcodeInfo kI_C3 = { 0xC3, "OP_C3_UNVERIFIED", Direction::In, kF_C3, 5, true, true, false, false };
constexpr OpcodeInfo kI_C5 = { 0xC5, "OP_C5_UNVERIFIED", Direction::In, kF_C5, 3, true, true, false, false };
constexpr OpcodeInfo kI_C7 = { 0xC7, "OP_C7_UNVERIFIED", Direction::In, kF_C7, 8, true, true, false, false };
constexpr OpcodeInfo kI_C8 = { 0xC8, "OP_C8_UNVERIFIED", Direction::In, kF_C8, 1, true, false, false, false };
constexpr OpcodeInfo kI_CB = { 0xCB, "OP_CB_UNVERIFIED", Direction::In, kF_CB, 1, true, false, false, false };
constexpr OpcodeInfo kI_CC = { 0xCC, "OP_CC_UNVERIFIED", Direction::In, kF_CC, 1, true, false, false, false };
constexpr OpcodeInfo kI_CE = { 0xCE, "OP_CE_UNVERIFIED", Direction::In, kF_CE, 1, true, true, false, false };
constexpr OpcodeInfo kI_CF = { 0xCF, "OP_CF_UNVERIFIED", Direction::In, kF_CF, 3, true, true, false, false };
constexpr OpcodeInfo kI_D0 = { 0xD0, "OP_D0_UNVERIFIED", Direction::In, kF_D0, 1, true, false, false, false };
constexpr OpcodeInfo kI_D1 = { 0xD1, "OP_D1_UNVERIFIED", Direction::In, kF_D1, 1, true, false, false, false };
constexpr OpcodeInfo kI_D3 = { 0xD3, "OP_D3_UNVERIFIED", Direction::In, kF_D3, 6, true, false, false, false };
constexpr OpcodeInfo kI_D5 = { 0xD5, "OP_D5_UNVERIFIED", Direction::In, kF_D5, 12, true, true, false, false };
constexpr OpcodeInfo kI_D6 = { 0xD6, "OP_D6_UNVERIFIED", Direction::In, kF_D6, 2, true, false, false, false };
constexpr OpcodeInfo kI_D7 = { 0xD7, "OP_D7_UNVERIFIED", Direction::In, kF_D7, 4, true, false, false, false };
constexpr OpcodeInfo kI_D9 = { 0xD9, "OP_D9_UNVERIFIED", Direction::In, kF_D9, 3, true, true, false, false };
constexpr OpcodeInfo kI_FE = { 0xFE, "OP_FE_UNVERIFIED", Direction::In, nullptr, 0, true, true, true, false };

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

// Giden yon icin ayri kayit yok; tablo In ile ayni kayitlari isaret eder.
constexpr const OpcodeInfo* kOutTable[256] = {};

} // namespace

const OpcodeInfo* findOpcode(std::uint8_t opcode, Direction dir) {
  const OpcodeInfo* hit = (dir == Direction::Out) ? kOutTable[opcode] : kInTable[opcode];
  if (hit != nullptr) return hit;
  // Istenen yonde kayit yoksa diger yone bak.
  return (dir == Direction::Out) ? kInTable[opcode] : kOutTable[opcode];
}

const char* opcodeName(std::uint8_t opcode) {
  const OpcodeInfo* e = findOpcode(opcode, Direction::In);
  return e ? e->name : "UNKNOWN";
}

bool isKnownOpcode(std::uint8_t opcode) { return findOpcode(opcode, Direction::In) != nullptr; }

Direction opcodeDirection(std::uint8_t opcode) {
  const OpcodeInfo* e = findOpcode(opcode, Direction::In);
  return e ? e->dir : Direction::In;
}

} // namespace ko
