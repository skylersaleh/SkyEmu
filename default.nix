{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib
}:

pkgs.stdenv.mkDerivation {
  pname = "skyemu";
  version = "3-unstable-2025-01-25";

  src = ./.;

  postPatch = ''
    # Nixpkgs does not support macOS universal builds
    substituteInPlace CMakeLists.txt \
      --replace-fail "set(CMAKE_OSX_ARCHITECTURES" "#"
  '';

  nativeBuildInputs = with pkgs; [
    cmake
    ninja
    pkg-config
  ];

  buildInputs = with pkgs; [
    curl
    openssl
    SDL2
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux (with pkgs; [
    alsa-lib
    xorg.libXcursor
    xorg.libXi
    xorg.xinput
  ]);

  cmakeFlags = [
    (lib.cmakeBool "USE_SYSTEM_CURL" true)
    (lib.cmakeBool "USE_SYSTEM_OPENSSL" true)
    (lib.cmakeBool "USE_SYSTEM_SDL2" true)
  ];

  meta = {
    mainProgram = "SkyEmu";
    license = lib.licenses.mit;
  };
}
