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