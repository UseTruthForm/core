package awscc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"

	"github.com/stackdna/core/internal/snapshot"
)

// Zone is an Availability Zone. Name is account-relative (us-east-2a names
// different physical zones in different accounts); ID names the physical
// zone (use2-az1) and means the same in every account, which is why
// subnets are captured with the ID.
type Zone struct{ Name, ID string }

// Zones lists a region's standard Availability Zones (Local Zones and
// Wavelength Zones need opting in and are no counterpart for a subnet).
// It is one EC2 Query API call, signed with the SDK's own signer and sent
// as a GET, so it passes the read-only guard and needs no EC2 SDK module.
// Only the aws partition's endpoint is known.
func (s *SDK) Zones(ctx context.Context, region string) ([]Zone, error) {
	if err := CheckRegion(region); err != nil {
		return nil, err
	}
	creds, err := s.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("zones in %s: %w", region, err)
	}
	u := "https://ec2." + region + ".amazonaws.com/?Action=DescribeAvailabilityZones&Version=2016-11-15" +
		"&Filter.1.Name=zone-type&Filter.1.Value.1=availability-zone"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	empty := sha256.Sum256(nil)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(empty[:]), "ec2", region, time.Now()); err != nil {
		return nil, err
	}
	// Without the read-only guard the config has no client of its own (each
	// service client builds one), and using it panicked in the first
	// cross-region drill; the SDK's default is what those clients use.
	hc := s.cfg.HTTPClient
	if hc == nil {
		hc = awshttp.NewBuildableClient()
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zones in %s: %w", region, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zones in %s: HTTP %d: %s", region, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Items []struct {
			Name string `xml:"zoneName"`
			ID   string `xml:"zoneId"`
		} `xml:"availabilityZoneInfo>item"`
	}
	if err := xml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("zones in %s: %w", region, err)
	}
	zs := make([]Zone, 0, len(out.Items))
	for _, it := range out.Items {
		zs = append(zs, Zone{Name: it.Name, ID: it.ID})
	}
	if len(zs) == 0 {
		return nil, fmt.Errorf("zones in %s: none listed", region)
	}
	return zs, nil
}

// SnapshotRegion is the region a snapshot was captured in.
func SnapshotRegion(s snapshot.Snapshot) string {
	return strings.TrimPrefix(s.ServerVersion, "cloudcontrol/")
}

// Retarget rewrites a snapshot captured in one region for another, so it
// can be restored there and diffed against it. Zone IDs and names are
// mapped one to one in zone-ID order (use2-az1 to usw2-az1, and so on),
// which keeps resources that were in different zones in different zones;
// explicit entries ("use2-az1": "usw2-az3") override that. The region is
// replaced where it is structural: a whole value, or an ARN's region
// segment (also inside a JSON string). A zone with no counterpart (a
// six-zone region restored into a three-zone one) is refused before
// anything is sent, with every object that uses it named: half a restore
// across regions would leave subnets in zones nobody chose.
func Retarget(s snapshot.Snapshot, to string, fromZones, toZones []Zone, explicit map[string]string) (snapshot.Snapshot, []string, error) {
	from := SnapshotRegion(s)
	if from == "" || from == to {
		return s, nil, nil
	}
	byID := func(zs []Zone) []Zone {
		c := append([]Zone(nil), zs...)
		sort.Slice(c, func(i, j int) bool { return c[i].ID < c[j].ID })
		return c
	}
	src, dst := byID(fromZones), byID(toZones)
	dstByID := map[string]Zone{}
	for _, z := range dst {
		dstByID[z.ID] = z
	}
	zmap := map[string]string{} // source zone ID or name -> target
	var unmapped []string
	var notes []string
	for i, z := range src {
		var t Zone
		if id, ok := explicit[z.ID]; ok {
			var known bool
			if t, known = dstByID[id]; !known {
				return s, nil, fmt.Errorf("zone map: %s is not a zone of %s", id, to)
			}
		} else if i < len(dst) {
			t = dst[i]
		} else {
			unmapped = append(unmapped, z.ID)
			continue
		}
		zmap[z.ID], zmap[z.Name] = t.ID, t.Name
		notes = append(notes, z.ID+" ("+z.Name+") -> "+t.ID+" ("+t.Name+")")
	}
	arn := regexp.MustCompile(`(arn:aws[a-z-]*:[a-z0-9-]*:)` + regexp.QuoteMeta(from) + `(:)`)
	var blocked []string
	out := s
	out.Objects = make([]snapshot.Object, len(s.Objects))
	for i, o := range s.Objects {
		body := deepCopy(o.Body)
		spec, _ := body["spec"].(map[string]any)
		uses := map[string]bool{}
		body["spec"] = walkStrings(spec, func(v string) string {
			for _, u := range unmapped {
				if v == u {
					uses[u] = true
				}
			}
			if t, ok := zmap[v]; ok {
				return t
			}
			if v == from {
				return to
			}
			return arn.ReplaceAllString(v, "${1}"+to+"${2}")
		})
		for u := range uses {
			blocked = append(blocked, o.Key()+" uses "+u)
		}
		out.Objects[i] = snapshot.Object{Body: body}
	}
	if len(blocked) > 0 {
		sort.Strings(blocked)
		return s, nil, fmt.Errorf("%s has %d zones and %s %d; no counterpart for %s (map them with --zone-map):\n  %s",
			from, len(src), to, len(dst), strings.Join(unmapped, ", "), strings.Join(blocked, "\n  "))
	}
	out.ServerVersion = "cloudcontrol/" + to
	return out, append([]string{from + " -> " + to}, notes...), nil
}

// ForRegion retargets a snapshot captured in another region for this
// adapter's region, reading both regions' zones. A snapshot of this region
// is returned unchanged.
func (a *Adapter) ForRegion(ctx context.Context, s snapshot.Snapshot) (snapshot.Snapshot, []string, error) {
	from := SnapshotRegion(s)
	if from == "" || from == a.Region {
		return s, nil, nil
	}
	fz, err := a.API.Zones(ctx, from)
	if err != nil {
		return s, nil, err
	}
	tz, err := a.API.Zones(ctx, a.Region)
	if err != nil {
		return s, nil, err
	}
	return Retarget(s, a.Region, fz, tz, a.ZoneMap)
}

// fakeZones gives a fake region three zones named as AWS names them:
// us-west-2a with ID usw2-az1, and so on.
func fakeZones(region string) []Zone {
	p := strings.Split(region, "-")
	code := region
	if len(p) == 3 {
		code = p[0] + p[1][:1] + p[2]
	}
	var zs []Zone
	for i, l := range []string{"a", "b", "c"} {
		zs = append(zs, Zone{Name: region + l, ID: fmt.Sprintf("%s-az%d", code, i+1)})
	}
	return zs
}
