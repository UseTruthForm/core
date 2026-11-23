package translate

import (
	"fmt"
	"regexp"
	"strconv"
)

// isoDuration matches the ISO 8601 durations Azure writes for a TimeSpan:
// PT1M, P14D, P10675199DT2H48M5.4775807S. Years and months are refused: they
// have no fixed length.
var isoDuration = regexp.MustCompile(`^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// seconds reads an ISO 8601 duration.
func seconds(s string) (float64, error) {
	m := isoDuration.FindStringSubmatch(s)
	if m == nil || s == "P" || s == "PT" {
		return 0, fmt.Errorf("%q is not a duration in days, hours, minutes and seconds", s)
	}
	var total float64
	for i, unit := range []float64{7 * 86400, 86400, 3600, 60, 1} {
		if m[i+1] == "" {
			continue
		}
		v, err := strconv.ParseFloat(m[i+1], 64)
		if err != nil {
			return 0, err
		}
		total += v * unit
	}
	return total, nil
}

// unbounded is where Service Bus's "never" starts: TimeSpan.MaxValue is
// P10675199DT2H48M5.4775807S, and any setting this long is that.
const unbounded = 10000 * 365 * 86400.0

func human(sec float64) string {
	switch {
	case sec >= unbounded:
		return "never"
	case sec >= 86400 && int64(sec)%86400 == 0:
		return fmt.Sprintf("%dd", int64(sec)/86400)
	case sec >= 3600 && int64(sec)%3600 == 0:
		return fmt.Sprintf("%dh", int64(sec)/3600)
	case sec >= 60 && int64(sec)%60 == 0:
		return fmt.Sprintf("%dm", int64(sec)/60)
	}
	return strconv.FormatFloat(sec, 'f', -1, 64) + "s"
}
