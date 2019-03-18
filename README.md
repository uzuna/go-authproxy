# AuthProxy

OpenIDConnect認証の情報をSessionで保持する認証Proxy

バックエンドにあるのは`JWT`で認証を行う`Envoy+gRPC`もしくは`RESTAPI`が
ある状況で、任意のブラウザからのアクセスをOIDCを使って認証をする。

- AuthProxyはOIDC認証を行い、認証後は速やかにただのプロキシとしてふるまう
- 認証済みのセッションは必ず`Authorization`ヘッダーにJWTを書き込んで次のサーバーにProxyする。
- ユーザーで必要なヘッダーの追加も可能にする


## Config

```yaml
# config.yml
client_id: "***"
client_secret: "***"
endpoint:
  auth_url: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
  token_url: https://login.microsoftonline.com/common/oauth2/v2.0/token
redirect_url: "***"
scopes:
  - openid
jwk_url: https://login.microsoftonline.com/common/discovery/v2.0/keys
response_type: id_token
issuers: 
  - https://login.microsoftonline.com/***/v2.0
```