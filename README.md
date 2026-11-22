# study-Auth

Go で Web アプリの認証・認可を学ぶリポジトリ。

| ディレクトリ | 学ぶ内容 |
| --- | --- |
| [oidc/](oidc/README.md) | Google ログインを通して OAuth 2.0 と OpenID Connect を学ぶ。Step 0〜8 の手順もここにある。 |
| [webauthn/](webauthn/README.md) | パスキーの登録とログインを学ぶ。実装はこれから。 |

リポジトリのルートで `make run` を実行すると OIDC のサーバーが起動する。設定方法は [OIDC の起動手順](oidc/README.md#ローカルで動かす)を参照。テストはルートで `make test` を実行する。
