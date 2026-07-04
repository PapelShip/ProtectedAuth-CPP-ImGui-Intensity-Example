# Intensity Loader

A minimalist, ImGui-based secure PE Loader integrated with qPapelAuth. Designed with a clean, dark-themed UI.

## Features
- ImGui DirectX9 Overlay Interface
- Automatic Key Validation & Licensing
- Fetch Key Information functionality
- Post-build payload encryption & injection via `qPapelPacker`

## Build Instructions
1. Open `Intensity Loader.sln` in Visual Studio 2022.
2. Set build configuration to **Release | x64**.
3. Ensure `vcpkg` is installed with the required ImGui / DirectX9 dependencies.
4. Build the solution. The final packed executable will be automatically placed in the `dist/` directory via post-build events.
