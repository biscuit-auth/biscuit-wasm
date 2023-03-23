{ pkgs ? import <nixpkgs> {} }: with pkgs;

mkShell {
  buildInputs = [
    pkgconfig
    rustup
    openssl
    nodejs-16_x
  ];
}
