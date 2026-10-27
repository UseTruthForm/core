package snapshot

import "regexp"

// throttledRE matches the platforms' ways of saying "slow down", as each
// documents them, by status and error code only:
//
//   - Azure: HTTP 429 Too Many Requests (ARM and the resource providers
//     behind it), *RequestsThrottled codes, and "excessive volume of
//     traffic" for background jobs;
//   - AWS: ThrottlingException and Throttling, "Rate exceeded",
//     RequestLimitExceeded (EC2), SlowDown (S3) and the SDK's own "retry
//     quota exceeded", all on HTTP 400, not 429;
//   - Google Cloud: 429 RESOURCE_EXHAUSTED, and Compute's 403
//     rateLimitExceeded and userRateLimitExceeded;
//   - Kubernetes: 429 from API Priority and Fairness;
//   - GitHub: 403 or 429 for its primary and secondary rate limits and its
//     abuse detection;
//   - Cloudflare: 429.
//
// The codes are matched as the platforms spell them, so a name chosen by
// a person (a resource group "rg-throttling", a Deployment "ratelimiter")
// is not read as one (review of #35); URLs are removed first for the same
// reason.
var throttledRE = regexp.MustCompile(`(?:HTTP |: )429\b|(?i:too many requests)|TooManyRequests|\bThrottling(?:Exception)?\b|RequestsThrottled\b|(?i:rate exceeded)|\bRequestLimitExceeded\b|\bSlowDown\b|\b(?:user)?[Rr]ateLimitExceeded\b|\bRESOURCE_EXHAUSTED\b|(?i:retry quota exceeded)|(?i:excessive volume of traffic)|(?i:secondary rate limit)|(?i:API rate limit exceeded)|(?i:abuse detection)`)

var urlRE = regexp.MustCompile(`https?://\S+`)

// dailyRE is a quota that a later capture that day will not find refilled:
// Google's per-day quotas answer RESOURCE_EXHAUSTED too. Matched by the
// quota's name, never a bare "daily", which a resource can be named
// (review of #38).
var dailyRE = regexp.MustCompile(`(?i)\bper ?day\b|PerDay|dailyLimitExceeded`)

// Throttled reports a failure that the platform's throttling caused, read
// from the failure's own text (not from a name the failure is about).
func Throttled(reason string) bool {
	r := urlRE.ReplaceAllString(reason, "")
	return throttledRE.MatchString(r) && !dailyRE.MatchString(r)
}
