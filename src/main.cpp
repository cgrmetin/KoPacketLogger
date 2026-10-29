#include <windows.h>

#include <d3d11.h>
#include <tchar.h>

#include <cstdio>
#include <string>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "app.h"
#include "ui/theme.h"
#include "ui/ui.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {

constexpr wchar_t kWindowClass[] = L"KoPacketLoggerWindow";
constexpr wchar_t kWindowTitle[] = L"KoPacketLogger - Paket Izleyici";

ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_context = nullptr;
IDXGISwapChain* g_swapChain = nullptr;
ID3D11RenderTargetView* g_renderTarget = nullptr;

ko::AppState g_app;
ko::ui::Ui* g_ui = nullptr;

bool g_occluded = false;
bool g_minimized = false;

void createRenderTarget() {
  ID3D11Texture2D* backBuffer = nullptr;
  g_swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
  if (backBuffer != nullptr) {
    g_device->CreateRenderTargetView(backBuffer, nullptr, &g_renderTarget);
    backBuffer->Release();
  }
}

void releaseRenderTarget() {
  if (g_renderTarget != nullptr) {
    g_renderTarget->Release();
    g_renderTarget = nullptr;
  }
}

bool createDeviceD3D(HWND hwnd) {
  DXGI_SWAP_CHAIN_DESC desc{};
  desc.BufferCount = 2;
  desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  desc.BufferDesc.RefreshRate.Numerator = 60;
  desc.BufferDesc.RefreshRate.Denominator = 1;
  desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
  desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  desc.OutputWindow = hwnd;
  desc.SampleDesc.Count = 1;
  desc.SampleDesc.Quality = 0;
  desc.Windowed = TRUE;
  desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
  D3D_FEATURE_LEVEL obtained{};

  const HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, static_cast<UINT>(std::size(levels)),
      D3D11_SDK_VERSION, &desc, &g_swapChain, &g_device, &obtained, &g_context);
  if (FAILED(hr)) return false;

  createRenderTarget();
  return true;
}

void destroyDeviceD3D() {
  releaseRenderTarget();
  if (g_swapChain != nullptr) {
    g_swapChain->Release();
    g_swapChain = nullptr;
  }
  if (g_context != nullptr) {
    g_context->Release();
    g_context = nullptr;
  }
  if (g_device != nullptr) {
    g_device->Release();
    g_device = nullptr;
  }
}

LRESULT WINAPI wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam)) return true;

  switch (msg) {
    case WM_SIZE:
      if (wParam == SIZE_MINIMIZED) {
        g_minimized = true;
        g_occluded = false;
      } else if (wParam == SIZE_MAXIMIZED) {
        g_minimized = false;
        g_occluded = false;
        releaseRenderTarget();
        g_swapChain->ResizeBuffers(0, static_cast<UINT>(LOWORD(lParam)), static_cast<UINT>(HIWORD(lParam)),
                                   DXGI_FORMAT_UNKNOWN, 0);
        createRenderTarget();
      } else if (wParam == SIZE_RESTORED) {
        if (g_minimized) {
          g_minimized = false;
          releaseRenderTarget();
          g_swapChain->ResizeBuffers(0, static_cast<UINT>(LOWORD(lParam)), static_cast<UINT>(HIWORD(lParam)),
                                     DXGI_FORMAT_UNKNOWN, 0);
          createRenderTarget();
        } else if (g_occluded) {
          g_occluded = false;
          releaseRenderTarget();
          g_swapChain->ResizeBuffers(0, static_cast<UINT>(LOWORD(lParam)), static_cast<UINT>(HIWORD(lParam)),
                                     DXGI_FORMAT_UNKNOWN, 0);
          createRenderTarget();
        }
      }
      return 0;

    case WM_SYSCOMMAND:
      if ((wParam & 0xFFF0) == SC_KEYMENU) return 0;
      break;

    case WM_DESTROY:
      ::PostQuitMessage(0);
      return 0;

    default:
      break;
  }
  return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
  // Pencere sinifi.
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_CLASSDC;
  wc.lpfnWndProc = wndProc;
  wc.hInstance = instance;
  wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
  wc.lpszClassName = kWindowClass;
  ::RegisterClassExW(&wc);

  HWND hwnd = ::CreateWindowW(kWindowClass, kWindowTitle, WS_OVERLAPPEDWINDOW, 80, 60, 1440, 900, nullptr, nullptr,
                              instance, nullptr);
  if (hwnd == nullptr) {
    ::MessageBoxW(nullptr, L"Pencere olusturulamadi.", kWindowTitle, MB_ICONERROR);
    ::UnregisterClassW(kWindowClass, instance);
    return 1;
  }

  if (!createDeviceD3D(hwnd)) {
    destroyDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(kWindowClass, instance);
    ::MessageBoxW(nullptr, L"DirectX 11 cihazi olusturulamadi.", kWindowTitle, MB_ICONERROR);
    return 1;
  }

  ::ShowWindow(hwnd, SW_SHOWDEFAULT);
  ::UpdateWindow(hwnd);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  io.IniFilename = "ko-imgui.ini";

  ko::ui::applyDarkTheme();
  ko::ui::loadUiFonts(16.0f);

  ImGui_ImplWin32_Init(hwnd);
  ImGui_ImplDX11_Init(g_device, g_context);

  ko::ui::Ui ui(g_app);
  g_ui = &ui;
  ui.initialize();

  bool running = true;
  while (running) {
    MSG msg;
    while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      ::TranslateMessage(&msg);
      ::DispatchMessageW(&msg);
      if (msg.message == WM_QUIT) running = false;
    }
    if (!running) break;
    if (g_occluded) {
      ::Sleep(60);
      continue;
    }

    if (g_swapChain->Present(1, 0) == DXGI_STATUS_OCCLUDED) {
      g_occluded = true;
      ::Sleep(60);
      continue;
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ui.frame();

    ImGui::Render();
    const ImVec4 clear(0.070f, 0.075f, 0.090f, 1.0f);
    g_context->OMSetRenderTargets(1, &g_renderTarget, nullptr);
    g_context->ClearRenderTargetView(g_renderTarget, &clear.x);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

    // Coklu viewport destegi: platform pencereleri.
    if ((io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) != 0) {
      ImGui::UpdatePlatformWindows();
      ImGui::RenderPlatformWindowsDefault();
    }

    if (g_app.quit.load(std::memory_order_relaxed)) running = false;
  }

  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();

  destroyDeviceD3D();
  ::DestroyWindow(hwnd);
  ::UnregisterClassW(kWindowClass, instance);
  return 0;
}
