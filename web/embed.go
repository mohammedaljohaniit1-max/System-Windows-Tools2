package web

import "embed"

//go:embed static/* assets/*
var EmbeddedFS embed.FS
