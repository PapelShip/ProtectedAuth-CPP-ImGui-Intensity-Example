#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <string>
#include <iostream>
#include <fstream>
#include <d3d9.h>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"
#include <thread>
#include <mutex>

#include "Include/qPapelLib.h"
#pragma comment(lib, "Lib/qPapelLib.lib")

static QPCTX g_ctx = nullptr;
static bool g_initialized = false;
static bool g_connected = false;
static bool g_authenticated = false;
static std::string g_statusMessage = "Ready";
static std::mutex g_authMutex;

static LPDIRECT3D9              g_pD3D = NULL;
static LPDIRECT3DDEVICE9        g_pd3dDevice = NULL;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};

// Forward declarations of helper functions
bool UiRender();
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void ResetDevice();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

ImFont* MenuFont = nullptr;

int Tab = 1;
int SubTab = 1;
int MenuTab = 1;
bool hidden = false;
char Username[255] = "username";
char Password[255] = "password";
char License[255] = "key";

bool tempspoof = false;
bool PermEfiSpoof = false;
bool PermKernelSpoof = false;

std::string diskserials = "";
std::string biosserial = "";
std::string windowsuuidserials = "";
std::string motherboardserial = "";
std::string windowsidserial = "";
void Theme()
{
    ImGuiStyle& style = ImGui::GetStyle();
    style.ItemSpacing = ImVec2(0, 0);
    style.WindowPadding = ImVec2(0, 0);
    style.FramePadding = ImVec2(3.5, 3.5);
    style.FrameRounding = 0.0f;

    style.WindowBorderSize = 1.0f;

    style.GrabRounding = 1.0f;
    style.GrabMinSize = 0.0f;

    style.Colors[ImGuiCol_WindowBg] = ImColor(18, 18, 18);

    style.Colors[ImGuiCol_CheckMark] = ImColor(255, 0, 0);

    style.Colors[ImGuiCol_FrameBg] = ImColor(18, 18, 18);
    style.Colors[ImGuiCol_FrameBgActive] = ImColor(18, 18, 18);
    style.Colors[ImGuiCol_FrameBgHovered] = ImColor(18, 18, 18);

    style.FrameBorderSize = 0.05f;

    style.Colors[ImGuiCol_ChildBg] = ImColor(21, 21, 21);

    style.Colors[ImGuiCol_Border] = ImColor(0, 0, 0);

    style.Colors[ImGuiCol_Button] = ImColor(33, 33, 33);
    style.Colors[ImGuiCol_ButtonActive] = ImColor(255, 0, 0, 100);
    style.Colors[ImGuiCol_ButtonHovered] = ImColor(33, 33, 33);
}

#pragma region SERIALNUMBERS

std::string getdiskserial () {
    std::array<char, 128> buffer;
    std::shared_ptr<FILE> pipe(_popen("wmic diskdrive get serialnumber", "r"), _pclose);
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
            diskserials += buffer.data();
    }
    return diskserials;
}
std::string getbioserial() {
    std::array<char, 128> buffer;
    std::shared_ptr<FILE> pipe(_popen("wmic bios get serialnumber", "r"), _pclose);
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
            biosserial += buffer.data();
    }
    return biosserial;
}
std::string getmotherboardserial() {
    std::array<char, 128> buffer;
    std::shared_ptr<FILE> pipe(_popen("wmic baseboard get serialnumber", "r"), _pclose);
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
            motherboardserial += buffer.data();
    }
    return motherboardserial;
}
std::string WindowsIdentifier() {
    std::array<char, 128> buffer;
    std::shared_ptr<FILE> pipe(_popen("wmic csproduct get IdentifyingNumber", "r"), _pclose);
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
            windowsidserial += buffer.data();
    }
    return windowsidserial;
}
std::string WindowsUUID() {
    std::array<char, 128> buffer;
    std::shared_ptr<FILE> pipe(_popen("wmic csproduct get uuid", "r"), _pclose);
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
            windowsuuidserials += buffer.data();
    }
    return windowsuuidserials;
}

void PerformLogin() {
    std::lock_guard<std::mutex> lock(g_authMutex);
    
    if (!g_initialized) {
        if (!qpapel::Init()) {
            g_statusMessage = "Core init failed!";
            return;
        }
        g_ctx = qpapel::CreateContext();
        if (!g_ctx) {
            g_statusMessage = "Context failed!";
            return;
        }
        qpapel::SetConfig(g_ctx, "apikey", "", 0, "version");
        qpapel::CheckIntegrity(g_ctx);
        g_initialized = true;
    }

    if (!g_connected) {
        if (!qpapel::Connect(g_ctx)) {
            char* err = qpapel::GetLastStatus(g_ctx);
            g_statusMessage = err ? err : "Connection failed!";
            if (err) qpapel::FreeString(err);
            return;
        }
        g_connected = true;
    }

    g_statusMessage = "Authenticating...";
    char* token = qpapel::Authenticate(g_ctx, License);
    if (token != nullptr && token[0] != '\0') {
        qpapel::FreeString(token);
        g_authenticated = true;
        g_statusMessage = "Authenticated!";
        Tab = 2;
    } else {
        char* err = qpapel::GetLastStatus(g_ctx);
        g_statusMessage = err ? err : "Auth failed!";
        if (err) qpapel::FreeString(err);
    }
}

#pragma endregion

int main(int, char**)
{
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L"qPapel", NULL};
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"qPapel", WS_POPUP, 0, 0, 1, 1, NULL, NULL, wc.hInstance, NULL);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    //AllocConsole();
    //ShowWindow(FindWindowA("ConsoleWindowClass", NULL), false);

    ::ShowWindow(hwnd, SW_HIDE);
    ::UpdateWindow(hwnd);
    // Setup Dear ImGui context
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    static const ImWchar icon_ranges[]{ 0xf000, 0xf3ff, 0 };
    ImFontConfig icons_config;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.OversampleH = 3;
    icons_config.OversampleV = 3;

    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\taileb.ttf", 13.f);

    //MenuFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\micross.ttf", 14.f);
    MenuFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\taileb.ttf", 13.3f);

    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);
    Theme();

    UiRender();

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}



/*
Rendering the ui
*/
bool UiRender()
{

    getbioserial();
    getdiskserial();
    //WindowsIdentifier();
    WindowsUUID();
    getmotherboardserial();

    while (true)
    {
        bool done = false;
        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            return false;


        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 0.00f);

        if (Tab == 1)
        {
            ImGui::SetNextWindowSize(ImVec2(350, 250), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowPos(
                ImVec2(GetSystemMetrics(SM_CXSCREEN) / 2.0f - 175.0f, GetSystemMetrics(SM_CYSCREEN) / 2.0f - 125.0f),
                ImGuiCond_FirstUseEver
            );
            ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(350, 250));
            ImGui::Begin("qPapel Loader", 0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize);

            ImGui::BeginChild("TopLine", ImVec2(350, 25), 1);
            {

                float posX = ImGui::GetCursorPosX() + (ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("qPapel.cc").x) * 0.5f;
                float posY = ImGui::GetCursorPosY() + (ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight()) * 0.5f;

                ImGui::SetCursorPos({ posX, posY });
                ImGui::Text("qPapel.");
                ImGui::PushStyleColor(ImGuiCol_Text, ImColor(255, 0, 0).Value);
                ImGui::SameLine();
                ImGui::Text("CC");
                ImGui::SetCursorPos({ 330, posY });
                ImGui::Text("X");
                if (ImGui::IsItemClicked()) exit(-1);
                ImGui::PopStyleColor();

            }
            ImGui::EndChild();

                ImGui::SetCursorPos(ImVec2(140, 70));
                ImGui::Text("License Key");
                
                ImGui::SetNextItemWidth(200);
                ImGui::SetCursorPos(ImVec2(75, 90));
                ImGui::InputText("##Key", License, IM_ARRAYSIZE(License), ImGuiInputTextFlags_Password);
                
                ImGui::SetCursorPosY(130);
                ImGui::SetCursorPosX(115);
                if (ImGui::Button("LOGIN", ImVec2(120, 30)))
                {
                    PerformLogin();
                }
                
                // Center the status message
                float statusWidth = ImGui::CalcTextSize(g_statusMessage.c_str()).x;
                ImGui::SetCursorPos(ImVec2((350 - statusWidth) / 2.0f, 180));
                ImGui::TextWrapped("%s", g_statusMessage.c_str());

            ImGui::End();
            ImGui::PopStyleVar();
        }

        if (Tab == 2)
        {
            ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(390, 300));
            ImGui::Begin("qPapel Menu", 0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize);
            ImGui::PushFont(MenuFont);

            ImGui::SetCursorPos(ImVec2(0, 0));
            ImGui::BeginChild("##NavBar", ImVec2(390, 30), 1);
            {
                ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 8));
                ImGui::Text("qPapel.");
                ImGui::PushStyleColor(ImGuiCol_Text, ImColor(255, 0, 0).Value);
                ImGui::SameLine();
                ImGui::Text("cc");
                ImGui::PopStyleColor();

                ImGui::SameLine();

                ImGui::PushStyleColor(ImGuiCol_Text, MenuTab == 1 ? ImVec4(255,0,0,255) : ImVec4(231, 231, 231, 255));
                ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 210, ImGui::GetCursorPosY()));
                ImGui::Text("Profile");
                if (ImGui::IsItemClicked()) MenuTab = 1;
                ImGui::PopStyleColor();

                ImGui::SameLine();

                ImGui::PushStyleColor(ImGuiCol_Text, MenuTab == 2 ? ImVec4(255, 0, 0, 255) : ImVec4(231, 231, 231, 255));
                ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 10, ImGui::GetCursorPosY()));
                ImGui::Text("Extras");
                if (ImGui::IsItemClicked()) MenuTab = 2;
                ImGui::PopStyleColor();

                ImGui::SameLine();

                ImGui::PushStyleColor(ImGuiCol_Text, MenuTab == 3 ? ImVec4(255, 0, 0, 255) : ImVec4(231, 231, 231, 255));
                ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 10, ImGui::GetCursorPosY()));
                ImGui::Text("Exit");
                if (ImGui::IsItemClicked()) exit(-1);
                ImGui::PopStyleColor();
            }
            ImGui::EndChild();

            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 5);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 5);
            ImGui::BeginChild("##left", ImVec2(187, ImGui::GetContentRegionAvail().y - 7), true);
            {

                if (MenuTab == 1)
                {
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 5));
                    ImGui::Text("Session Status:");
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 5));
                    if (g_authenticated) {
                        ImGui::TextColored(ImVec4(0, 1, 0, 1), "Active");
                    } else {
                        ImGui::TextColored(ImVec4(1, 0, 0, 1), "Disconnected");
                    }
                    
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 15));
                    ImGui::Text("License Key:");
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 5));
                    ImGui::TextDisabled("%s", License);
                }

                if (MenuTab == 2)
                {
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 10, ImGui::GetCursorPosY() + 5));
                }

            }
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 5);
            ImGui::BeginChild("##right", ImVec2(187, ImGui::GetContentRegionAvail().y - 7), true);
            {
                
                if (MenuTab == 1)
                {
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 5));
                    ImGui::PushStyleColor(ImGuiCol_Text, ImColor(255, 0, 0).Value);
                    ImGui::Text("Key Information:");
                    ImGui::PopStyleColor();
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 5, ImGui::GetCursorPosY() + 2));
                    ImGui::TextWrapped("%s", g_statusMessage.c_str());
                    
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 10, ImGui::GetCursorPosY() + 150));
                    if (ImGui::Button("Fetch Information", ImVec2(167, 20)))
                    {
                        if (g_authenticated && g_ctx) {
                            char* val = qpapel::FetchString(g_ctx, "1", License);
                            if (val) {
                                g_statusMessage = std::string("Data: ") + val;
                                qpapel::FreeString(val);
                            } else {
                                g_statusMessage = "Fetch failed.";
                            }
                        }
                    }
                }

                if (MenuTab == 2)
                {
                    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 10, ImGui::GetCursorPosY() + 5));
                }

            }
            ImGui::EndChild();

            ImGui::PopFont();
            ImGui::End();
            ImGui::PopStyleVar();
        }
    

        ImGui::EndFrame();

        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
        g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }
        ImGuiIO& io = ImGui::GetIO();

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();
    }
    return true;
}

bool CreateDeviceD3D(HWND hWnd)
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
        return false;

    // Create the D3DDevice
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = NULL; }
}

void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0 // From Windows SDK 8.1+ headers
#endif

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_DPICHANGED:
        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
        {
            const RECT* suggested_rect = (RECT*)lParam;
            ::SetWindowPos(hWnd, NULL, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
