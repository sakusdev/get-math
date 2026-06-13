# get-math

一見すると中学数学のまとめサイトとして動作し、特定のクエリを受け取った場合だけサーバー側でログイン画面へ切り替わるCloudflare Workerです。

通常アクセス時に返すHTMLには、秘密入口・認証ロジック・秘密ページのHTMLは含まれません。

## セットアップ

```bash
npm install
npx wrangler login
```

Worker Secretsを4つ登録します。

```bash
npx wrangler secret put ENTRY_PARAM
# witan と入力

npx wrangler secret put ENTRY_TOKEN
# gea と入力

npx wrangler secret put AUTH_PASSWORD
# ログインに使用するパスワードを入力

npx wrangler secret put SESSION_SECRET
# 十分に長いランダム文字列を入力
```

ランダム文字列の生成例：

```bash
openssl rand -base64 48
```

デプロイ：

```bash
npm run deploy
```

## 動作

- `GET /`：通常の中学数学まとめサイト
- `GET /?witan=gea`：短時間有効な入口Cookieを発行し、`/`へ303リダイレクト
- リダイレクト後の`GET /`：ログインページ
- `POST /`：Worker内で認証
- 認証成功後の`GET /`：秘密ページ

入口のクエリはSecretsで設定するため、公開リポジトリ内には実値を埋め込みません。ブラウザではリダイレクト後にパラメーターなしのURLになります。

## 注意

入口文字列は認証そのものではありません。秘密ページは必ずパスワードと署名付き`HttpOnly` Cookieで保護されます。

URLはCloudflareへ最初の1回だけ送信されるため、Cloudflare側のリクエストログ等には残る可能性があります。認証パスワードはURLではなくPOST本文で送信します。
