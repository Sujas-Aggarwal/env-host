package main

import (
	"env-host/internal/cli"
	"os"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
