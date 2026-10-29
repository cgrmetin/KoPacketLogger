#include "ui/theme.h"

#include <cstdio>
#include <filesystem>

namespace ko::ui {
namespace {

ImVec4 rgb(int r, int g, int b, float a = 1.0f) {
  return ImVec4(r / 255.0f, g / 255.0f, b / 255.0f, a);
}

void setupStyle() {
  ImGuiStyle& s = ImGui::GetStyle();
  s.WindowPadding = ImVec2(10, 10);
  s.FramePadding = ImVec2(7, 4);
  s.CellPadding = ImVec2(6, 3);
  s.ItemSpacing = ImVec2(8, 6);
  s.ItemInnerSpacing = ImVec2(6, 4);
  s.IndentSpacing = 18.0f;
  s.ScrollbarSize = 14.0f;
  s.GrabMinSize = 11.0f;
  s.WindowBorderSize = 1.0f;
  s.ChildBorderSize = 1.0f;
  s.PopupBorderSize = 1.0f;
  s.FrameBorderSize = 0.0f;
  s.TabBorderSize = 0.0f;
  s.WindowRounding = 5.0f;
  s.ChildRounding = 4.0f;
  s.FrameRounding = 4.0f;
  s.PopupRounding = 4.0f;
  s.ScrollbarRounding = 6.0f;
  s.GrabRounding = 4.0f;
  s.TabRounding = 4.0f;
  s.WindowTitleAlign = ImVec2(0.0f, 0.5f);
  s.WindowMenuButtonPosition = ImGuiDir_None;
  s.SeparatorTextBorderSize = 2.0f;
  s.SeparatorTextPadding = ImVec2(14, 4);
  s.DockingSeparatorSize = 3.0f;

  ImVec4* c = s.Colors;
  c[ImGuiCol_Text] = rgb(220, 224, 232);
  c[ImGuiCol_TextDisabled] = rgb(110, 118, 132);
  c[ImGuiCol_WindowBg] = rgb(22, 24, 29);
  c[ImGuiCol_ChildBg] = rgb(18, 20, 24);
  c[ImGuiCol_PopupBg] = rgb(26, 29, 35);
  c[ImGuiCol_Border] = rgb(48, 53, 63);
  c[ImGuiCol_BorderShadow] = rgb(0, 0, 0, 0.0f);
  c[ImGuiCol_FrameBg] = rgb(33, 37, 45);
  c[ImGuiCol_FrameBgHovered] = rgb(44, 49, 60);
  c[ImGuiCol_FrameBgActive] = rgb(52, 58, 71);
  c[ImGuiCol_TitleBg] = rgb(17, 19, 23);
  c[ImGuiCol_TitleBgActive] = rgb(30, 34, 42);
  c[ImGuiCol_TitleBgCollapsed] = rgb(17, 19, 23, 0.85f);
  c[ImGuiCol_MenuBarBg] = rgb(24, 27, 33);
  c[ImGuiCol_ScrollbarBg] = rgb(16, 18, 22);
  c[ImGuiCol_ScrollbarGrab] = rgb(58, 64, 77);
  c[ImGuiCol_ScrollbarGrabHovered] = rgb(74, 81, 96);
  c[ImGuiCol_ScrollbarGrabActive] = rgb(92, 100, 118);
  c[ImGuiCol_CheckMark] = rgb(96, 176, 255);
  c[ImGuiCol_SliderGrab] = rgb(72, 140, 210);
  c[ImGuiCol_SliderGrabActive] = rgb(96, 176, 255);
  c[ImGuiCol_Button] = rgb(42, 48, 58);
  c[ImGuiCol_ButtonHovered] = rgb(56, 64, 78);
  c[ImGuiCol_ButtonActive] = rgb(70, 80, 97);
  c[ImGuiCol_Header] = rgb(38, 44, 54);
  c[ImGuiCol_HeaderHovered] = rgb(52, 60, 73);
  c[ImGuiCol_HeaderActive] = rgb(64, 74, 90);
  c[ImGuiCol_Separator] = rgb(48, 53, 63);
  c[ImGuiCol_SeparatorHovered] = rgb(80, 120, 170);
  c[ImGuiCol_SeparatorActive] = rgb(96, 176, 255);
  c[ImGuiCol_ResizeGrip] = rgb(70, 80, 97, 0.55f);
  c[ImGuiCol_ResizeGripHovered] = rgb(96, 176, 255, 0.75f);
  c[ImGuiCol_ResizeGripActive] = rgb(96, 176, 255);
  c[ImGuiCol_Tab] = rgb(28, 32, 39);
  c[ImGuiCol_TabHovered] = rgb(52, 60, 73);
  c[ImGuiCol_TabSelected] = rgb(42, 49, 60);
  c[ImGuiCol_TabDimmed] = rgb(24, 27, 33);
  c[ImGuiCol_TabDimmedSelected] = rgb(35, 40, 49);
  c[ImGuiCol_DockingPreview] = rgb(96, 176, 255, 0.55f);
  c[ImGuiCol_DockingEmptyBg] = rgb(16, 18, 22);
  c[ImGuiCol_PlotLines] = rgb(150, 190, 240);
  c[ImGuiCol_PlotLinesHovered] = rgb(96, 176, 255);
  c[ImGuiCol_PlotHistogram] = rgb(120, 180, 130);
  c[ImGuiCol_PlotHistogramHovered] = rgb(150, 210, 160);
  c[ImGuiCol_TableHeaderBg] = rgb(30, 34, 42);
  c[ImGuiCol_TableBorderStrong] = rgb(52, 58, 71);
  c[ImGuiCol_TableBorderLight] = rgb(40, 45, 55);
  c[ImGuiCol_TableRowBg] = rgb(0, 0, 0, 0.0f);
  c[ImGuiCol_TableRowBgAlt] = rgb(255, 255, 255, 0.028f);
  c[ImGuiCol_TextLink] = rgb(96, 176, 255);
  c[ImGuiCol_TextSelectedBg] = rgb(96, 176, 255, 0.32f);
  c[ImGuiCol_DragDropTarget] = rgb(255, 200, 90);
  c[ImGuiCol_NavCursor] = rgb(96, 176, 255);
  c[ImGuiCol_NavWindowingHighlight] = rgb(255, 255, 255, 0.7f);
  c[ImGuiCol_NavWindowingDimBg] = rgb(0, 0, 0, 0.45f);
  c[ImGuiCol_ModalWindowDimBg] = rgb(0, 0, 0, 0.55f);
}

// Windows ile gelen Unicode fontlardan ilk bulunani dener.
bool tryLoadFont(const char* const* candidates, float sizePixels) {
  ImGuiIO& io = ImGui::GetIO();
  for (const char* const* p = candidates; *p != nullptr; ++p) {
    std::error_code ec;
    if (!std::filesystem::exists(*p, ec)) {
      continue;
    }
    ImFontConfig cfg;
    cfg.OversampleH = 2;
    cfg.OversampleV = 1;
    cfg.PixelSnapH = false;
    // Turkce karakter araligini acikca iste; varsayilan aralik yalnizca Latin-1.
    static const ImWchar ranges[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x0100, 0x017F, // Latin Extended-A (g-breve, i-dot, s-cedilla)
        0x2010, 0x205E, // punctuation
        0x20A0, 0x20BF, // currency
        0x2190, 0x21FF, // arrows
        0x2500, 0x25FF, // box drawing + geometric shapes
        0x2600, 0x26FF, // misc symbols
        0,
    };
    if (io.Fonts->AddFontFromFileTTF(*p, sizePixels, &cfg, ranges) != nullptr) {
      return true;
    }
  }
  return false;
}

} // namespace

void applyDarkTheme() {
  setupStyle();
  ImGui::StyleColorsDark();
  setupStyle();
}

void loadUiFonts(float sizePixels) {
  ImGuiIO& io = ImGui::GetIO();
  static const char* const candidates[] = {
      "C:/Windows/Fonts/segoeui.ttf",
      "C:/Windows/Fonts/tahoma.ttf",
      "C:/Windows/Fonts/arial.ttf",
      nullptr,
  };
  if (!tryLoadFont(candidates, sizePixels)) {
    io.Fonts->AddFontDefault();
  }
}

ImU32 colorForDirection(bool incoming) {
  return incoming ? IM_COL32(128, 214, 142, 255) : IM_COL32(126, 176, 240, 255);
}

ImU32 colorForRow(bool incoming, bool knownOpcode, bool ok, bool selected) {
  if (selected) {
    return IM_COL32(66, 78, 96, 255);
  }
  if (!ok) {
    return IM_COL32(58, 34, 36, 255);
  }
  if (!knownOpcode) {
    return incoming ? IM_COL32(34, 48, 40, 255) : IM_COL32(32, 42, 54, 255);
  }
  return incoming ? IM_COL32(24, 30, 27, 255) : IM_COL32(23, 28, 36, 255);
}

} // namespace ko::ui
