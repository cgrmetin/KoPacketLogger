#pragma once

#include "imgui.h"

namespace ko::ui {

// Koyu, dusuk kontrastli, uzun sure bakilabilir tema. Bir kez cagrilir.
void applyDarkTheme();

// Turkce karakterleri (g s, i, o, u, c) kapsayan arayuz fontunu yukler.
// Font bulunamazsa ImGui varsayilan fontuna duser; uygulama calismaya devam eder.
void loadUiFonts(float sizePixels);

// Yon ve opcode durumuna gore satir rengi.
ImU32 colorForDirection(bool incoming);
ImU32 colorForRow(bool incoming, bool knownOpcode, bool ok, bool selected);

} // namespace ko::ui
