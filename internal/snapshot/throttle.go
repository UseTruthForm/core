package snapshot

import "regexp"

// throttledRE matches the platforms' ways of saying "slow down", as each
// documents them:
//
//   - Azure: HTTP 429 Too Many Requests (ARM and the resource providers
//     behind it), and "excessive volume of traffic" for background jobs;
//   - AWS: ThrottlingException, "Rate exceeded", and the SDK's own
//     "retry quota exceeded", all on HTTP 400, not 429;
//   - Google Cloud: 429 RESOURCE_EXHAUSTED, and Compute's 403
//     rateLimitExceeded and userRateLimitExceeded;
//   - Kubernetes: 429 from API Priority and Fairness;
//   - GitHub: 403 or 429 for its primary and secondary rate limits;
//   - Cloudflare: 429.
//
// A throttled read is not a missing permission and not a broken type: the
// same capture run again later, or with fewer calls in flight, reads it.
var throttledRE = regexp.MustCompile(`(?i)(?:HTTP |: )429\b|too many requests|toomanyrequests|throttl|rate exceeded|rate ?limit|ratelimitexceeded|resource_exhausted|retry quota|excessive volume of traffic`)

// Throttled reports a failure that the platform's throttling caused.
func Throttled(reason string) bool { return throttledRE.MatchString(reason) }
