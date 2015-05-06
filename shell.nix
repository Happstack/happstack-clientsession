with (import <nixpkgs> {}).pkgs;
let pkg = haskellngPackages.callPackage
            ({ mkDerivation, base, bytestring, cereal, clientsession
             , happstack-server, monad-control, mtl, safecopy, stdenv
             , transformers-base
             }:
             mkDerivation {
               pname = "happstack-clientsession";
               version = "7.2.8";
               src = ./.;
               buildDepends = [
                 base bytestring cereal clientsession happstack-server monad-control
                 mtl safecopy transformers-base
               ];
               homepage = "http://happstack.com";
               description = "client-side session data";
               license = stdenv.lib.licenses.bsd3;
             }) {};
in
  pkg.env
