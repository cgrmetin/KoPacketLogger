cmake_minimum_required(VERSION 3.28)
project(KoPacketLogger VERSION 0.2 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Genel ayarlar: C++23, x64, statik CRT (/MT), tek exe.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Bu proje yalnizca x64 hedefler. -A x64 ile yapilandirin.")
endif()

if(NOT MSVC)
  message(FATAL_ERROR "Desteklenen toolchain MSVC'dir.")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out/lib")

# ---------------------------------------------------------------------------
# Ucuncu parti yollar.
# ---------------------------------------------------------------------------
set(NPCAP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/npcap-sdk-1.17" CACHE PATH "Npcap SDK kok dizini")
set(NPCAP_INCLUDE_DIR "${NPCAP_ROOT}/Include")
set(NPCAP_LIB_DIR "${NPCAP_ROOT}/Lib/x64")

if(NOT EXISTS "${NPCAP_INCLUDE_DIR}/pcap.h")
  message(FATAL_ERROR "Npcap SDK bulunamadi: ${NPCAP_INCLUDE_DIR}/pcap.h")
endif()
if(NOT EXISTS "${NPCAP_LIB_DIR}/wpcap.lib")
  message(FATAL_ERROR "Npcap lib bulunamadi: ${NPCAP_LIB_DIR}/wpcap.lib")
endif()

# ImGui'yi baska bir ajan vendor ediyor; yoksa yapilandirma yine gecmeli.
set(IMGUI_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui")
set(IMGUI_AVAILABLE FALSE)
if(EXISTS "${IMGUI_ROOT}/imgui.cpp")
  set(IMGUI_AVAILABLE TRUE)
else()
  message(STATUS "third_party/imgui henuz yok - UI kaynaklari atlanacak.")
endif()

# ---------------------------------------------------------------------------
# ko_core: kripto + cerceve ayristirma. Bagimsiz, UI'ya bagimli degil.
# ---------------------------------------------------------------------------
add_library(ko_core STATIC
  src/core/types.h
  src/core/aes.h
  src/core/aes.cpp
  src/core/frame.h
  src/core/frame.cpp
  src/core/opcodes.h
  src/core/opcodes.cpp
  src/core/decoder.h
  src/core/decoder.cpp
)
target_include_directories(ko_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(ko_core PUBLIC cxx_std_23)
set_target_properties(ko_core PROPERTIES FOLDER "core")

# ---------------------------------------------------------------------------
# Uygulama: capture + ui + main. Dosyalar diger ajanlardan geldikce glob ile toplanir.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE APP_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/capture/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/capture/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/*.h"
)
set(HAVE_MAIN FALSE)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
  set(HAVE_MAIN TRUE)
  list(APPEND APP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
endif()

if(NOT APP_SOURCES)
  message(STATUS "capture/ui kaynaklari yok - yalnizca ko_core hedefi uretilecek.")
  return()
endif()

# main.cpp yokken exe uretilmez; kaynaklar bir arada derlensin diye statik
# lib yapilir (link hatasi olmaz, derleme hatasi gorunur kalir).
if(HAVE_MAIN)
  set(APP_TARGET_TYPE EXECUTABLE)
else()
  set(APP_TARGET_TYPE STATIC)
  message(STATUS "src/main.cpp yok - capture/ui kaynaklari ko_app statik kutuphanesi olarak derleniyor.")
endif()

if(APP_TARGET_TYPE STREQUAL "EXECUTABLE")
  add_executable(KoPacketLogger WIN32 ${APP_SOURCES})
else()
  add_library(ko_app STATIC ${APP_SOURCES})
  add_library(app ALIAS ko_app)
endif()

# Yonetici manifesti yalnizca exe'ye gomulur; statik lib yolunda kaynak derlenmez.
if(APP_TARGET_TYPE STREQUAL "EXECUTABLE")
  set(_app_rc "${CMAKE_CURRENT_SOURCE_DIR}/src/app.rc")
  target_sources(KoPacketLogger PRIVATE "${_app_rc}")
  # RC derleyicisi hedef include dizinlerini kullanmaz; goreli manifest yolu
  # src dizinine gore cozulsun diye /I yalnizca bu kaynak dosyaya verilir.
  set_property(SOURCE "${_app_rc}" APPEND PROPERTY COMPILE_FLAGS
    "/I\"${CMAKE_CURRENT_SOURCE_DIR}/src\""
  )
endif()

if(APP_TARGET_TYPE STREQUAL "EXECUTABLE")
  set(_app_target KoPacketLogger)
  # Manifest .rc icinden RT_MANIFEST olarak gomulur; linker kendi manifestini
  # uretirse CVT1100 (duplicate resource MANIFEST) verir. Uretimi kapat.
  set(_exe_link_options /SUBSYSTEM:WINDOWS /MANIFEST:NO)
else()
  set(_app_target ko_app)
  set(_exe_link_options "")
endif()

target_include_directories(${_app_target} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${NPCAP_INCLUDE_DIR}"
)

if(IMGUI_AVAILABLE)
  set(IMGUI_SOURCES
    "${IMGUI_ROOT}/imgui.cpp"
    "${IMGUI_ROOT}/imgui_draw.cpp"
    "${IMGUI_ROOT}/imgui_tables.cpp"
    "${IMGUI_ROOT}/imgui_widgets.cpp"
    "${IMGUI_ROOT}/backends/imgui_impl_win32.cpp"
    "${IMGUI_ROOT}/backends/imgui_impl_dx11.cpp"
  )
  add_library(imgui STATIC ${IMGUI_SOURCES})
  target_include_directories(imgui PUBLIC "${IMGUI_ROOT}" "${IMGUI_ROOT}/backends")
  # Win32 + DirectX 11 arka ucu.
  target_link_libraries(imgui PUBLIC d3d11 dxgi)
  set_target_properties(imgui PROPERTIES FOLDER "third_party")
  target_link_libraries(${_app_target} PRIVATE imgui)
else()
  message(WARNING "imgui bulunamadi: UI kodu derlenemeyebilir.")
endif()

target_link_directories(${_app_target} PRIVATE "${NPCAP_LIB_DIR}")
target_link_libraries(${_app_target} PRIVATE ko_core wpcap Packet ws2_32 iphlpapi)
set_target_properties(${_app_target} PROPERTIES FOLDER "app")

# Statik kutuphane hedefi icin link kurallari uygulanmaz; exe icin subsystem ayarlanir.
if(APP_TARGET_TYPE STREQUAL "EXECUTABLE")
  target_link_options(${_app_target} PRIVATE ${_exe_link_options})
endif()
