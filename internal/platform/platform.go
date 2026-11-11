// Package platform is the contract every Truthform adapter implements
// (Kubernetes today; AWS, Azure, GCP and SaaS providers next). It is kept
// to two operations on purpose: anything an adapter can capture it must be
// able to restore, and diff needs no adapter code at all: capture the target
// and compare snapshots.
package platform

import (
	"context"

	"github.com/usetruthform/core/internal/snapshot"
)

// Platform captures a live system into a snapshot and restores one back.
type Platform interface {
	// Name is the snapshot's platform field ("kubernetes", "aws", ...).
	Name() string
	// Capture reads everything capturable. Types it cannot read go into the
	// snapshot's coverage with a reason; an error means no usable snapshot.
	Capture(ctx context.Context) (snapshot.Snapshot, error)
	// Restore applies every object and reports each one as applied or not,
	// with the reason. It must never drop an object without a result.
	Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result
}
