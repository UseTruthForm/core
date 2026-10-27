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
	} {
		if got := Throttled(reason); got != want {
			t.Errorf("%q: throttled=%v, want %v", reason, got, want)
		}
	}
}
