package snapshot

import (
	"fmt"
	"regexp"
	"strings"
)

// The reasons a Kubernetes capture gives for leaving out what something
// else makes: a controller through an owner reference, a GitOps source
// through the labels it stamps on what it applies (a source that applies
// itself among them). Capture writes them with these formats, and
// SplitMoved reads them with the same, so the two cannot drift apart.
//
// Only the GitOps reasons can be a move, and only where the captured copy
// carries the same marks (SplitMoved). An owner reference is not kept in a
// capture, so a move across "owned by" cannot be checked, and is not one.
const (
	OwnedFormat             = "owned by %s/%s, whose controller recreates it"
	FluxHelmReleaseFormat   = "rendered by Flux HelmRelease %s/%s; restoring the HelmRelease recreates it"
	FluxKustomizationFormat = "applied by Flux Kustomization %s/%s; restoring it recreates this"
	ArgoCDFormat            = "managed by Argo CD application %s; restoring the application recreates it"
)

// OwnedReason is the reason for an object a controller makes.
func OwnedReason(kind, name string) string { return fmt.Sprintf(OwnedFormat, kind, name) }

// FluxHelmReleaseReason is the reason for an object a Flux HelmRelease renders.
func FluxHelmReleaseReason(ns, name string) string {
	return fmt.Sprintf(FluxHelmReleaseFormat, ns, name)
}

// FluxKustomizationReason is the reason for an object a Flux Kustomization applies.
func FluxKustomizationReason(ns, name string) string {
	return fmt.Sprintf(FluxKustomizationFormat, ns, name)
}

// ArgoCDReason is the reason for an object an Argo CD application manages.
func ArgoCDReason(app string) string { return fmt.Sprintf(ArgoCDFormat, app) }

// madeElsewhere matches, exactly, each reason that can be a move. A reason
// added later is not one until it is added here.
var madeElsewhere = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, f := range []string{FluxHelmReleaseFormat, FluxKustomizationFormat, ArgoCDFormat} {
		// A name as Kubernetes allows one in a label or a reference: no
		// space, and none of the separators the reason itself uses.
		out = append(out, regexp.MustCompile("^"+strings.ReplaceAll(regexp.QuoteMeta(f), "%s", `[^\s/;,]+`)+"$"))
	}
	return out
}()

// MadeElsewhere says whether a skip reason, given by a capture of
// platform, means that a GitOps source applies the object: the only
// reasons a move between captured and left out may be read across, and
// then only where the captured copy says the same (SplitMoved).
// Kubernetes' only: no other platform's capture gives one.
func MadeElsewhere(platform, reason string) bool {
	if platform != "kubernetes" {
		return false
	}
	for _, re := range madeElsewhere {
		if re.MatchString(reason) {
			return true
		}
	}
	return false
}
