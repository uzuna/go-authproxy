## AuthProxy

OpenIDConnect認証の情報をSessionで保持する認証Proxy


1. session idでユーザーアクセスを識別する
2. sidとtokenを結び付けて、ユーザの認証情報を自動的に付与する
3. sidとtokenの更新を行う
4. proxyする <-これは別の機能

session idはstore側で生成するのが普通らしい


1. Tokenがあれば通す
2. Tokenの期限が近ければ更新を行う
3. Tokenの期限切れの場合はRefreshを試行し、だめなら認証へ移動する
2. Tokenがなければ認証へ移動する

1. Token structを保持
2. Expireを保持


##### Redirect

1. 任意のアドレスにアクセス
2. ログインしていなかったのでLoginフローへ移動
3. 元のアドレスを開く
    - SPA + Hashの場合はSPAにhashの保持が必要
    - Addressの保持が必要
    - POST / からRedirect?
    - 任意のアドレスをリストで表示するにとどめるほうが良い? -> Continue

* 認証失敗時はRedirectしない
    - 

post -> authcheck -> reroute
route -> refresh -> reroute

Authorize時の検証

- issuer
- Audience
- ACL組み込み?

- OauthConfig
    - 認証アドレス生成とRefresh
    - session -> state
- Authenticate
    - 認証okenの検証

- Routing
    - 認証状態からエラーメッセいーじを生成
    - session -> path
- ErrorPages
    - 表示のカスタマイズ

