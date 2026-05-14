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
//
// Driver-library deps (added in v0.7.2 step 3 for the
// `drivers/pgx` and `drivers/pq` adapter packages):
//
//   * pgx/v5 — the modern Go Postgres driver (jackc/pgx). The
//     adapter package `drivers/pgx` consumes pgxpool.Pool and
//     pgconn.PgError.
//   * lib/pq — the legacy database/sql Postgres driver
//     registration (lib/pq). The adapter `drivers/pq` consumes
//     `*sql.DB` from the standard library and the lib/pq
//     `*pq.Error` type for SQLSTATE classification.
//
// Both are runtime deps (the adapter packages import them
// directly). Test-time deps (testcontainers, etc.) come later
// in v0.7.5 step 6 for the conformance suite.
module github.com/pgrls/pgrls/go

go 1.22

require (
	github.com/jackc/pgerrcode v0.0.0-20240316143900-6e2875d9b438
	github.com/jackc/pgx/v5 v5.7.1
	github.com/lib/pq v1.10.9
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/text v0.18.0 // indirect
)
