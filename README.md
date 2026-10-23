# study-Auth — OAuth 2.0 / OpenID Connect をライブラリ無しで理解する

「Google アカウントでログインすると、自分のプロフィール画面にメールアドレスと名前を表示する Web アプリ」を
Go で OAuth ライブラリを使わずに作り、OAuth 2.0 (Authorization Code Flow + PKCE) と OIDC の各ステップを
ブラウザの Network タブとサーバーログで確認する。

## 実装要件（縛り）

- OAuth ライブラリ禁止
- JWT デコードは自前（署名検証は crypto/rsa 等のライブラリ利用可）
- PKCE を自前実装
- state を自前実装
- `/authorize` の URL を自前生成
- `/token` は `http.Client` で直接 POST
- userinfo を `Authorization: Bearer` 付きで直接呼ぶ
- ブラウザの Network タブとサーバーログで、各リクエスト・レスポンスを確認する

## 登場するエンドポイント（Google）

| 役割 | URL |
| --- | --- |
| Discovery | https://accounts.google.com/.well-known/openid-configuration |
| 認可 (authorize) | https://accounts.google.com/o/oauth2/v2/auth |
| トークン (token) | https://oauth2.googleapis.com/token |
| userinfo | https://openidconnect.googleapis.com/v1/userinfo |
| JWKS (公開鍵) | https://www.googleapis.com/oauth2/v3/certs |
| issuer | https://accounts.google.com |

## 進め方

各ステップで「仕様の要点」→「実装」→「Network タブ / ログで観察」の順に進める。
チェックを付けながら進める。

### Step 0: 準備

- [ ] Google Cloud Console で OAuth 同意画面を設定（外部 / テストユーザーに自分を追加）
- [ ] 「OAuth 2.0 クライアント ID（ウェブ アプリケーション）」を作成
- [ ] 承認済みのリダイレクト URI に `http://localhost:8080/callback` を登録
- [ ] `.env` に `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `REDIRECT_URI` を置く（`.env` は commit しない）
- [ ] `go mod init` して `net/http` だけで `/` を返す最小サーバを起動する

観察: Discovery ドキュメントを開き、上の表の URL が載っていることを確認する。

### Step 1: セッションと state（CSRF 対策）

- [ ] Cookie（`HttpOnly`, `SameSite=Lax`）+ サーバ側メモリでセッションを持つ
- [ ] `/login` で `crypto/rand` から state を生成してセッションに保存する
- [ ] `/callback` で返ってきた `state` とセッション内の値を照合する（定数時間比較、使い捨て）

理解したいこと: state が無いと何が起きるか（ログイン CSRF）。
`SameSite=Lax` でも Google からの戻り（トップレベル GET）で Cookie が送られるのはなぜか。

### Step 2: PKCE（認可コード横取り対策）

- [ ] `code_verifier`（43〜128 文字の乱数）を生成してセッションに保存する
- [ ] `code_challenge = BASE64URL(SHA256(code_verifier))` を計算する（パディング無し）
- [ ] RFC 7636 Appendix B のテストベクタで単体テストを書く
  - verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
  - challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`

理解したいこと: challenge は /authorize に、verifier は /token に送る。なぜ分けると安全になるのか。

### Step 3: /authorize URL の自前生成

- [ ] `url.Values` で以下を組み立てて 302 リダイレクトする
  - `client_id`, `redirect_uri`, `response_type=code`
  - `scope=openid email profile`
  - `state`, `nonce`
  - `code_challenge`, `code_challenge_method=S256`

観察（Network タブ）: `/login` の 302 の `Location` ヘッダ、Google 側での複数回のリダイレクト、
最後に `/callback?code=...&state=...` へ戻ってくるリクエスト。
`code` が URL に露出していることを確認する（だから PKCE が要る）。

### Step 4: /callback と /token（認可コード → トークン交換）

- [ ] `error` パラメータが来た場合の表示
- [ ] state 照合（Step 1）
- [ ] `http.Client` で `/token` に `application/x-www-form-urlencoded` で POST
  - `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `client_secret`, `code_verifier`
- [ ] レスポンス JSON（`access_token`, `id_token`, `expires_in`, `scope`, `token_type`）を構造体に受ける
- [ ] 送信リクエストと受信レスポンスをログに全文ダンプする（`httputil.DumpRequestOut` / `DumpResponse`）

観察（サーバーログ）: ブラウザからは見えないサーバ間通信。Google が web クライアントでは PKCE ありでも
`client_secret` を要求することを確認する。

### Step 5: ID トークン（JWT）の自前デコードと検証

- [ ] `.` で 3 分割し、header / payload を base64url → JSON でデコードする
- [ ] `alg` が `RS256` 以外なら拒否する（`alg=none` 対策）
- [ ] JWKS を取得し、header の `kid` に一致する鍵の `n`, `e` から `rsa.PublicKey` を組み立てる
- [ ] `SHA256("header.payload")` に対して `rsa.VerifyPKCS1v15` で署名検証する
- [ ] クレーム検証: `iss`, `aud`(= client_id), `exp`, `nonce`(= Step 3 で送った値)
- [ ] 改ざんしたトークン・期限切れ・aud 不一致が弾かれる単体テストを書く

理解したいこと: 「デコードできる」と「検証済み」は別物。nonce が防ぐ攻撃は何か。

### Step 6: userinfo と /profile

- [ ] `GET userinfo` を `Authorization: Bearer <access_token>` 付きで直接呼ぶ
- [ ] ログイン完了時にセッション ID を再発行する（セッション固定攻撃対策）
- [ ] `/profile` に名前とメールアドレスを表示する
- [ ] `/logout` でセッションを破棄する

観察: ID トークンの claims と userinfo の内容を見比べる。両方に `email`, `name` があるが役割は何が違うか。

### Step 7: 振り返り

- [ ] state / PKCE / nonce がそれぞれどの攻撃を防ぐかを自分の言葉で書く
- [ ] Implicit Flow（`response_type=token`）が非推奨になった理由を説明できる
- [ ] 本番で追加で必要になること（JWKS キャッシュ、セッションの永続化、HTTPS/`Secure` Cookie、refresh_token）を列挙する

## 参考仕様

- RFC 6749: The OAuth 2.0 Authorization Framework
- RFC 7636: Proof Key for Code Exchange (PKCE)
- RFC 7519: JSON Web Token (JWT) / RFC 7517: JSON Web Key (JWK)
- OpenID Connect Core 1.0（特に §3.1.3.7 ID Token Validation）
- Google: https://developers.google.com/identity/openid-connect/openid-connect
