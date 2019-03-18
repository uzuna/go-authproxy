# ErrorPages

## Motivation

Error時にテキストそのままで表示されるのは見栄えが悪く、
必要に応じたリンクの表示などは基本的に一貫しているため、
表示するページをグローバルで指定しておきたい


## How to use

`ErrorPages`に対して特定のstatus時によばれる`ErrorHandlerFunc`を指定する
もしくは`Static`で特定の決まったデータを表示させる
