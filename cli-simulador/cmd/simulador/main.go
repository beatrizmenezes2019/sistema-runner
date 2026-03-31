package main

import (
    "github.com/beatrizmenezes2019/sistema-runner/cli-simulador/internal/cli"
    "log"
)

func main() {
    if err := cli.Execute(); err != nil {
        log.Fatal(err)
    }
}