package snapshot

import (
	"fmt"
	"regexp"
	"strings"
)

// The reasons a Kubernetes capture gives for leaving out what something
// else makes: a controller through an owner reference, a GitOps source
// through the labels it stamps on what it applies (a source that applies
// itself among them). Capture writes them with these formats, and Compare
// reads them with the same, so the two cannot drift apart.
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

// gitOpsReasons matches, exactly, each reason a GitOps source gives: the
// only ones a build before beta.23 may have given an object a later build
// captures (SkippedOtherSide.OlderRules). A reason added later is not one
// until it is added here.
var gitOpsReasons = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, f := range []string{FluxHelmReleaseFormat, FluxKustomizationFormat, ArgoCDFormat} {
		// A name as Kubernetes allows one in a label or a reference: no
		// space, and none of the separators the reason itself uses.
		out = append(out, regexp.MustCompile("^"+strings.ReplaceAll(regexp.QuoteMeta(f), "%s", `[^\s/;,]+`)+"$"))
	}
	return out
}()

// appliedByGitOps says whether a skip reason, given by a capture of
// platform, is one a GitOps source gives. Kubernetes' only: no other
// platform's capture gives one.
func appliedByGitOps(platform, reason string) bool {
	if platform != "kubernetes" {
		return false
	}
	for _, re := range gitOpsReasons {
		if re.MatchString(reason) {
			return true
		}
	}
	return false
}
