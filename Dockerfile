FROM nimlang/nim:latest

WORKDIR /app

COPY . /app/fodprrelay

WORKDIR /app/fodprrelay

# nim-lmdb は実行時に liblmdb.so を動的ロードするため、ランタイムライブラリをインストールする
RUN apt-get update && apt-get install -y --no-install-recommends liblmdb0 \
    && rm -rf /var/lib/apt/lists/*

# 依存ライブラリ (ws / lmdb / secp256k1 など) と、Fodpr ライブラリを
# GitHub (https://github.com/LunaYoineko/Fodpr) から取得する。
# ローカルテスト時は FodprRelay.nimble の requires がコメントアウトされているため、
# ここで明示的に Fodpr をインストールする。
RUN nimble install -y

# リレーサーバーをリリースビルドする (config.nims のローカルパススイッチは
# コンテナ内では無効なので、nimble のデフォルトパスで解決する)
RUN rm -f nimble.paths && nim c -d:release --opt:speed -o:bin/server src/server.nim

EXPOSE 8000

CMD ["./bin/server"]
