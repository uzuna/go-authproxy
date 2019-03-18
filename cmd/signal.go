package main

import (
	"os"
	"os/signal"
	"syscall"
)

func WaitSignal() <-chan os.Signal {
	quit := make(chan os.Signal)

	signal.Notify(quit,
		syscall.SIGHUP,  // Hungup プロセスに設定ファイルの読み込みを要求
		syscall.SIGINT,  // Interrupt (Ctrl + C)割り込み
		syscall.SIGTERM, // Termination. docker stopで呼ばれる
		syscall.SIGQUIT, // Quit (Ctrl+/)
		os.Interrupt,    // on windows
	)

	return quit
}
