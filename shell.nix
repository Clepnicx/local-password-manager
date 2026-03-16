with (import <nixpkgs> { });
let
  # python packages
  python-pkgs = [
    (pkgs.python3.withPackages (
      python-pkgs: with python-pkgs; [
        stdiomask
        cryptography
      ]
    ))
  ];
in

mkShell {
  # all build packages
  buildInputs = [
    python-pkgs
  ];
}
