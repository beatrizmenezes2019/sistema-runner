package main

import (
    "github.com/beatrizmenezes2019/sistema-runner/internal/cli" // Verifique se o path está certo
    "log"
)

func main() {
    if err := cli.Execute(); err != nil {
        log.Fatal(err)
    }
}