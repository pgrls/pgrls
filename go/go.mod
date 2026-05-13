// Module path: github.com/pgrls/pgrls/go
//
// The Go port of pgrls-test lives in this subdirectory of the
// monorepo, mirroring the layout of the TypeScript port at
// /ts/. Subdirectory modules are first-class in Go since 1.18;
// users `go get github.com/pgrls/pgrls/go@<tag>` and import
// `github.com/pgrls/pgrls/go/pgrlstest`.
//
// Tag convention: `go/v0.7.0`, `go/v0.7.1`, etc. — distinct
// from the Python (`v0.5.10`) and TypeScript (`ts-v0.6.2`)
// release tracks so the three ports can ship independently.
module github.com/pgrls/pgrls/go

go 1.22
