package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestNewDynamoDBRateLimiterWithOptionsRejectsBadInput(t *testing.T) {
	tests := []struct {
		name   string
		table  string
		limit  int
		window time.Duration
		want   error
	}{
		{name: "empty table", table: "", limit: 60, window: time.Minute, want: ErrTableRequired},
		{name: "zero limit", table: "rate", limit: 0, window: time.Minute},
		{name: "negative limit", table: "rate", limit: -1, window: time.Minute},
		{name: "zero window", table: "rate", limit: 60, window: 0},
		{name: "negative window", table: "rate", limit: 60, window: -time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDynamoDBRateLimiterWithOptions(&fakeDynamoDBClient{}, tc.table, tc.limit, tc.window, nil)
			if err == nil {
				t.Fatalf("NewDynamoDBRateLimiterWithOptions() returned nil error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("NewDynamoDBRateLimiterWithOptions() error = %v, want errors.Is(%v)", err, tc.want)
			}
		})
	}
}

func TestNewDynamoDBRateLimiterDefaultsApply(t *testing.T) {
	limiter, err := newDynamoDBRateLimiter(&fakeDynamoDBClient{}, "rate")
	if err != nil {
		t.Fatalf("newDynamoDBRateLimiter() error = %v", err)
	}
	if got, want := limiter.limit, DefaultLimit; got != want {
		t.Fatalf("default limit = %d, want %d", got, want)
	}
	if got, want := limiter.window, DefaultWindow; got != want {
		t.Fatalf("default window = %v, want %v", got, want)
	}
}

func TestAllowRejectsEmptyEngineerSubject(t *testing.T) {
	limiter := newLimiter(t, &fakeDynamoDBClient{}, fixedClock{})

	err := limiter.Allow(context.Background(), broker.RateLimitRequest{Mode: broker.ModeOperator})
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Allow() error = %v, want %d broker.Error", err, http.StatusUnauthorized)
	}
}

// TestAllowIssuesConditionalIncrementWithinWindow locks the wire shape of the
// DynamoDB rate-limit update: per-engineer-per-window key, conditional ADD,
// expires_at sized at 2× the window so an entry survives one full window of
// inactivity. Don't delete; if any of these drift, the rate-limit semantics
// silently change.
func TestAllowIssuesConditionalIncrementWithinWindow(t *testing.T) {
	fake := &fakeDynamoDBClient{}
	now := time.Date(2026, 5, 1, 12, 30, 45, 0, time.UTC)
	limiter, err := NewDynamoDBRateLimiterWithOptions(fake, "rate", 5, time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiterWithOptions() error = %v", err)
	}

	if err := limiter.Allow(context.Background(), broker.RateLimitRequest{
		Mode:   broker.ModeOperator,
		Caller: broker.CallerClaims{Subject: "  engineer-1234  "},
	}); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}

	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("UpdateItem calls = %d, want %d", got, want)
	}
	call := fake.calls[0]
	if got, want := *call.TableName, "rate"; got != want {
		t.Fatalf("table = %q, want %q", got, want)
	}
	wantWindow := now.Truncate(time.Minute).Unix()
	wantWindowKey := broker.ModeOperator + ":" + strconv.FormatInt(wantWindow, 10)
	if got := stringKey(t, call.Key["window"]); got != wantWindowKey {
		t.Fatalf("window key = %q, want %q", got, wantWindowKey)
	}
	if got, want := stringKey(t, call.Key["engineer_sub"]), "engineer-1234"; got != want {
		t.Fatalf("engineer_sub key = %q (trim missed), want %q", got, want)
	}
	if got, want := numberAttr(t, call.ExpressionAttributeValues[":limit"]), "5"; got != want {
		t.Fatalf(":limit = %q, want %q", got, want)
	}
	wantExpires := strconv.FormatInt(now.Add(2*time.Minute).Unix(), 10)
	if got, want := numberAttr(t, call.ExpressionAttributeValues[":expires_at"]), wantExpires; got != want {
		t.Fatalf(":expires_at = %q, want %q", got, want)
	}
}

func TestAllowMaps429OnConditionalCheckFailed(t *testing.T) {
	fake := &fakeDynamoDBClient{err: &types.ConditionalCheckFailedException{}}
	limiter := newLimiter(t, fake, fixedClock{now: time.Now()})

	err := limiter.Allow(context.Background(), broker.RateLimitRequest{
		Mode:   broker.ModeOperator,
		Caller: broker.CallerClaims{Subject: "engineer-1234"},
	})
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Allow() error = %v, want %d broker.Error", err, http.StatusTooManyRequests)
	}
}

func TestAllowPropagatesDynamoDBError(t *testing.T) {
	want := errors.New("dynamodb is unavailable")
	fake := &fakeDynamoDBClient{err: want}
	limiter := newLimiter(t, fake, fixedClock{now: time.Now()})

	err := limiter.Allow(context.Background(), broker.RateLimitRequest{
		Mode:   broker.ModeOperator,
		Caller: broker.CallerClaims{Subject: "engineer-1234"},
	})
	if !errors.Is(err, want) {
		t.Fatalf("Allow() error = %v, want errors.Is(%v)", err, want)
	}
	if !strings.Contains(err.Error(), "ratelimit:") {
		t.Fatalf("Allow() error = %q, want ratelimit: prefix", err.Error())
	}
}

// TestAllowConsumesConfiguredLimitAndWindow asserts that the per-request
// UpdateItem reflects the Limit and Window passed at construction
// (operator-tunable knobs from broker config), not the package defaults.
// Mismatched plumbing here would silently lock operators back to 60/min.
func TestAllowConsumesConfiguredLimitAndWindow(t *testing.T) {
	fake := &fakeDynamoDBClient{}
	now := time.Date(2026, 5, 1, 12, 30, 45, 0, time.UTC)
	limiter, err := NewDynamoDBRateLimiterWithOptions(fake, "rate", 250, 5*time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiterWithOptions() error = %v", err)
	}

	if err := limiter.Allow(context.Background(), broker.RateLimitRequest{
		Mode:   broker.ModeOperator,
		Caller: broker.CallerClaims{Subject: "engineer-1234"},
	}); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("UpdateItem calls = %d, want %d", got, want)
	}
	if got, want := numberAttr(t, fake.calls[0].ExpressionAttributeValues[":limit"]), "250"; got != want {
		t.Fatalf(":limit = %q, want %q", got, want)
	}
	wantWindow := now.Truncate(5 * time.Minute).Unix()
	wantWindowKey := broker.ModeOperator + ":" + strconv.FormatInt(wantWindow, 10)
	if got := stringKey(t, fake.calls[0].Key["window"]); got != wantWindowKey {
		t.Fatalf("window key = %q, want %q (5m bucketing)", got, wantWindowKey)
	}
	wantExpires := strconv.FormatInt(now.Add(2*5*time.Minute).Unix(), 10)
	if got, want := numberAttr(t, fake.calls[0].ExpressionAttributeValues[":expires_at"]), wantExpires; got != want {
		t.Fatalf(":expires_at = %q, want %q", got, want)
	}
}

// TestAllowWindowKeyChangesAcrossWindowBoundary regression-guards the
// per-window bucketing: two calls separated by one window should hash into
// distinct rows so the conditional ADD starts fresh in the new window.
func TestAllowWindowKeyChangesAcrossWindowBoundary(t *testing.T) {
	fake := &fakeDynamoDBClient{}
	clock := &mutableClock{now: time.Date(2026, 5, 1, 12, 30, 45, 0, time.UTC)}
	limiter, err := NewDynamoDBRateLimiterWithOptions(fake, "rate", 5, time.Minute, clock)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiterWithOptions() error = %v", err)
	}

	request := broker.RateLimitRequest{
		Mode:   broker.ModeOperator,
		Caller: broker.CallerClaims{Subject: "engineer-1234"},
	}
	if err := limiter.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() first error = %v", err)
	}
	clock.now = clock.now.Add(time.Minute)
	if err := limiter.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() second error = %v", err)
	}

	if got, want := len(fake.calls), 2; got != want {
		t.Fatalf("UpdateItem calls = %d, want %d", got, want)
	}
	first := stringKey(t, fake.calls[0].Key["window"])
	second := stringKey(t, fake.calls[1].Key["window"])
	if first == second {
		t.Fatalf("window key did not change across window boundary: both %q", first)
	}
}

func newLimiter(t *testing.T, fake *fakeDynamoDBClient, clock broker.Clock) *DynamoDBRateLimiter {
	t.Helper()
	limiter, err := NewDynamoDBRateLimiterWithOptions(fake, "rate", 5, time.Minute, clock)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiterWithOptions() error = %v", err)
	}
	return limiter
}

func stringKey(t *testing.T, value types.AttributeValue) string {
	t.Helper()
	asString, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		t.Fatalf("attribute = %T, want *AttributeValueMemberS", value)
	}
	return asString.Value
}

func numberAttr(t *testing.T, value types.AttributeValue) string {
	t.Helper()
	asNumber, ok := value.(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("attribute = %T, want *AttributeValueMemberN", value)
	}
	return asNumber.Value
}

type fakeDynamoDBClient struct {
	calls []*dynamodb.UpdateItemInput
	err   error
}

func (c *fakeDynamoDBClient) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	c.calls = append(c.calls, input)
	if c.err != nil {
		return nil, c.err
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	if c.now.IsZero() {
		return time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	}
	return c.now
}

type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time { return c.now }
