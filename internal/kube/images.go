package kube

import (
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A rebuilt cluster pulls its images from somewhere. In a disaster that
// is the registry the source pulled from, if it is still there, and
// nothing changes but who may pull. A rebuild that takes nothing from the
// source for granted has a registry of its own, with the images built or
// copied into it, and every workload has to name it: the starts of a
// rename file are applied to image references as they are to store
// references.

// containerLists are the fields of a pod's spec that list containers.
var containerLists = []string{"containers", "initContainers", "ephemeralContainers"}

// stepLists are lists of containers under other names (Tekton's steps
// and sidecars), and containerKeys a single one (an Argo template's
// container and script).
var (
	stepLists     = []string{"steps", "sidecars"}
	containerKeys = []string{"container", "script"}
)

// eachImage passes every image reference in the object to f, with the
// field it is in, and stores what f returns. It reads pod specs wherever
// they are (a Deployment's template, a CronJob's, a ScaledJob's, another
// API's workload): any map with a containers list whose entries have a
// name and an image. An image named any other way (a chart's values, an
// operator's own field) is not one it sees.
func eachImage(v any, at string, f func(field, image string) string) {
	switch x := v.(type) {
	case map[string]any:
		if _, pod := x["containers"].([]any); pod {
			for _, l := range containerLists {
				for _, c := range list(x[l]) {
					m, _ := c.(map[string]any)
					img, ok := m["image"].(string)
					if _, named := m["name"].(string); !ok || !named || img == "" {
						continue
					}
					m["image"] = f(at+"."+l+"[].image", img)
				}
			}
			// A volume that is an image.
			for _, vol := range list(x["volumes"]) {
				m, _ := vol.(map[string]any)
				src, _ := m["image"].(map[string]any)
				if ref, ok := src["reference"].(string); ok && ref != "" {
					src["reference"] = f(at+".volumes[].image.reference", ref)
				}
			}
		}
		// Containers under other names, where there is no pod spec.
		if _, pod := x["containers"].([]any); !pod {
			for _, l := range stepLists {
				for _, c := range list(x[l]) {
					m, _ := c.(map[string]any)
					if img, ok := m["image"].(string); ok && img != "" {
						m["image"] = f(at+"."+l+"[].image", img)
					}
				}
			}
		}
		for _, k := range containerKeys {
			if m, _ := x[k].(map[string]any); m != nil {
				if img, ok := m["image"].(string); ok && img != "" {
					m["image"] = f(at+"."+k+".image", img)
				}
			}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			eachImage(x[k], at+"."+k, f)
		}
	case []any:
		for _, c := range x {
			eachImage(c, at+"[]", f)
		}
	}
}

// RegistryOf is the registry an image reference names, as a pull reads
// it: the part before the first slash when that is a host (it has a dot
// or a port, or is localhost), and Docker Hub otherwise.
func RegistryOf(image string) string {
	first, _, more := strings.Cut(image, "/")
	if more && (strings.ContainsAny(first, ".:") || first == "localhost") {
		// A host is the same in any case, and Docker Hub by either name.
		if first = strings.ToLower(first); first == "index.docker.io" || first == "registry-1.docker.io" {
			return "docker.io"
		}
		return first
	}
	return "docker.io"
}

// Pinned reports an image reference that names a digest: the only kind
// that is the same image whenever it is pulled.
func Pinned(image string) bool { return strings.Contains(image, "@sha256:") }

// PlanImages is where a snapshot's images are pulled from: what a
// rebuilt cluster has to be able to pull.
type PlanImages struct {
	Registry string `json:"registry"`
	// Images are the distinct references, and Unpinned those of them with
	// no digest: a tag is whatever was pushed to it last, so what a
	// rebuild pulls is not known to be what ran.
	Images   int `json:"images"`
	Unpinned int `json:"unpinned"`
}

// ImagesOf lists the registries a snapshot's workloads pull from.
func ImagesOf(s snapshot.Snapshot) []PlanImages {
	seen := map[string]bool{}
	by := map[string]*PlanImages{}
	for _, o := range s.Objects {
		eachImage(deepCopy(o.Body), "", func(_, img string) string {
			if !seen[img] {
				seen[img] = true
				r := RegistryOf(img)
				if by[r] == nil {
					by[r] = &PlanImages{Registry: r}
				}
				by[r].Images++
				if !Pinned(img) {
					by[r].Unpinned++
				}
			}
			return img
		})
	}
	out := make([]PlanImages, 0, len(by))
	for _, p := range by {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Registry < out[j].Registry })
	return out
}
