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
    - 認証状態からエラーメッセージを生成
    - session -> path
- ErrorPages
    - 表示のカスタマイズ


OAuth2.0との違い

### response_type

RFC6749では将来的な拡張を除いて`code` or `token`いずれかで、それは処理フローによって決まる
- 認可コードフローなら`code`
- implicitフローなら`token`
処理のレスポンスが違うので同時は成り立たなかった。

ところがOpenID Connectでは`id_token`を追加したうえで任意の組み合わせを指定できるようにした。加えて`none`を指定可能にした

OAuth2.0から大きな改装が必要になる

### Client Application Meta

認可リクエストの前に認可サーバーに事前登録が必要


1. Client ID
2. Client Secret
3. Client Type
4. Redirect URI

だけだったのが[ずっと増えた](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)

#### Client Type

ConfidentialかPublicのどちらかが指定されるべきということが暗黙の合意

### AccessToken

そもそもAccessTokenはJSON形式である必要はない
AccessTokenの取り消しができるように無意味で一意な文字列にすることがある


### IDToken

OpenID ConnectはIDTOkenを発行するための仕様という解釈

- IDTokenの書式がJWS(JSON WebSignature)
- IDTokenはJWTの一種なので必ずPayloadが読める

#### JWS

.で区切られた各場所がbase64 encodeされている
別にPayloadがJSONであるひつようはない(RFC 7515)


#### JWE

都度発行される共有カギを使って本文を暗号化
さらに共有カギ自体を公開鍵を使って暗号化して送る。

- 長い本文でも共有カギ暗号なので比較的低コストに変換できる
- 共有カギ自体を安全に渡せる


#### JWT

JSON形式のClaimの集合をJWS/JWEに埋め込んだもの


## CIBA

1. バックチャネルエンドポイントに送り
2. 認証デバイスから認証結果を伝える。

クライアントと認証が物理的に離れていることも想定されている
実質的に2FA二のかかった認可という感じか

implicitはBrawser上でキーを受け取るための物
Queryの中に埋め込んでおいて、サーバーはそれを読むためのjsコードを返す

認可エンドポイント
TokenEndpoint



## auth proxyの役割

1. OIDC認証フローの実行
2. 認証情報の保持
3. 認証情報を付加して後段にProxy
    - HTTPServerとしての機能
4. 認証情報の提供


#### OIDC認証フローの実行

- 任意のフローで認証を実行する機構
    - code, id_tokenと入れたら優先順位の高いものから実行?
    - いずれかの形でtokenさえ返ってくればよいとする

pathを一つ与えたらよしなにするmoduleを考える
Validateの結果は3パターン
1. 認証失敗 -> 401
2. IDTOkenは取れたがCodeの認証失敗 -> 許可しているならIDTokenを使う。そうでなければ401
3. Refresh/AccessToken取得 -> AccessTokenを使う


- 認証のためのURLを発行し
- 帰ってきたリクエストを処理し`Token interface`を返す

- 何も前提としない実装にする

- Refreshは2ptn
    - Refresh Tokenを使う。遷移なし
    - 再度認証フローを通す。遷移必要

```go

type OIDCAuth interface {
    AuthURL(state string) (string, error)
    Validate(req *http.Request) (Token, error)
}

type Token interface {
    Token() (token string, tokenType int)
    ExpireAt() (time.Duration, bool)
    Refresh() error
}
```

#### 認証情報の保持

Proxyであるから基本はSession内に保持する
- `Token(token_string, expire_at)`を返すのも検討するか?
  APIに対してもProxyするならなくても問題ない
- CLIがTokenを得るには?
    - localhostで鵜あるのが今は良さそうな気がするが実装が重い
    - Python CLIとかからするとサーバーと通信したい感がある
        - 発行アドレスをProxyに投げる
        - proxyは通常通り処理
        - 発行アドレスをもとにlocalhostに投げなおす
    - SAMLで認証をする


- CLIに対応するために`Authorization`がある場合はそのまま通過させる


#### Proxy

Routingは後段に任せてここでは認証情報の付与だけを行う
任意の名前とパラメータをHederに書き込む