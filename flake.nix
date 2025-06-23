{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default-linux";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
  };

  outputs = { self, nixpkgs, flake-utils, ... }: 
  flake-utils.lib.eachDefaultSystem (system: 
    let 
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
    packages.libtropic-util = pkgs.callPackage ./default.nix {};
    }
  );
}