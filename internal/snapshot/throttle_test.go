package snapshot

import "testing"

// Each platform's throttling signal, as its documentation gives it, reads
// as throttled; a refusal or a broken type does not.
func TestThrottled(t *testing.T) {
	for reason, want := range map[string]bool{
		"listed but could not be read: GET https://management.azure.com/x?api-version=1: 429 Too Many Requests: GetEntityAsync failed": true,
		"list failed: The request could not be processed due to an excessive volume of traffic":                                        true,
		"list failed: operation error CloudControl: ListResources, ThrottlingException: Rate exceeded":                                 true,
		"list failed: retry quota exceeded, 0 available, 5 requested":                                                                  true,
		"list failed: HTTP 429: RESOURCE_EXHAUSTED: Quota exceeded for quota metric 'Read requests'":                                   true,
		"list failed: HTTP 403: rateLimitExceeded: Rate Limit Exceeded":                                                                true,
		"list failed: HTTP 403: userRateLimitExceeded":                                                                                 true,
		"list failed: the server has received too many requests and has asked us to try again later":                                   true,
		"list failed: HTTP 403: You have exceeded a secondary rate limit":                                                              true,
		"list failed: HTTP 403: API rate limit exceeded for user":                                                                      true,
		"list failed: HTTP 403: AuthorizationFailed":                                                                                   false,
		"list failed: HTTP 403: PERMISSION_DENIED":                                                                                     false,
		"list failed: HTTP 404: ResourceNotFound":                                                                                      false,
		"list failed: HTTP 500: InternalServerError":                                                                                   false,
		"listed but could not be read: GET /x/4290: 400 Bad Request InvalidParameter":                                                  false,
		"listed but could not be read: GET /queues/429/rules: 400 Bad Request InvalidParameter":                                        false,
		// Names chosen by people are not signals (review of #35).
		"listed but could not be read: GET https://management.azure.com/subscriptions/s/resourceGroups/rg-throttling/providers/x: 403 Forbidden AuthorizationFailed": false,
		"list failed: deployments.apps \"ratelimiter\" is forbidden: User \"u\" cannot list resource":                                                                false,
		"list failed: HTTP 403: Resource not accessible by integration (repo api-rate-limit-proxy)":                                                                  false,
		// Signals the first version missed.
		"list failed: RequestLimitExceeded: Request limit exceeded.":                   true,
		"list failed: SlowDown: Please reduce your request rate.":                      true,
		"list failed: HTTP 403: You have triggered an abuse detection mechanism":       true,
		"list failed: SubscriptionRequestsThrottled: Number of read requests exceeded": true,
		// A daily quota is not refilled by running again soon.
		"list failed: HTTP 429: RESOURCE_EXHAUSTED: Quota exceeded for quota metric 'Queries per day'": false,
		"list failed: HTTP 403: Daily Limit Exceeded (dailyLimitExceeded)":                             false,
		// A resource named "daily" is not a daily quota (review of #38).
		"list failed: HTTP 429: RESOURCE_EXHAUSTED: rate limit on bucket daily-backups": true,
	} {
		if got := Throttled(reason); got != want {
			t.Errorf("%q: throttled=%v, want %v", reason, got, want)
		}
	}
}
