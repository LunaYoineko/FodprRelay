# Package

version       = "0.1.0"
author        = "LunaYoineko"
description   = "Fodpr Relay Server"
license       = "MIT"
srcDir        = "src"
bin           = @["server"]


# Dependencies

requires "nim >= 2.2.10"
requires "ws"
requires "lmdb"
# Fodpr ライブラリが利用する推移的依存も直接 requires しておく
# (テスト時は Fodpr をローカル参照するため nimble が解決できない)。
requires "secp256k1"
requires "nimcrypto"
requires "nimSHA2"
# テスト時は config.nims の switch("path", "/root/Fodpr/src") でローカル参照するため、
# 以下をコメントアウトしている。公開時はコメントを外すこと。
requires "https://github.com/LunaYoineko/Fodpr"
