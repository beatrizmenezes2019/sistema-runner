package main

import (
	"log"

	"github.com/beatrizmenezes2019/sistema-runner/cli-simulador/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		log.Fatal(err)
	}
}
