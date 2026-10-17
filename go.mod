module github.com/parallelworks/rbac

go 1.25.0

toolchain go1.27.2

// Enforce FIPS 140-3 mode everywhere, including `go test`: non-approved
// algorithms fail at runtime.
godebug fips140=only
