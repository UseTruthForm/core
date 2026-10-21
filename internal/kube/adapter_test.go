package kube

import "github.com/stackdna/core/internal/platform"

// Compile-time check that the Kubernetes adapter satisfies the contract.
var _ platform.Platform = (*Adapter)(nil)
