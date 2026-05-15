package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

func TestNewCloudWatchAuditRejectsEmptyLogGroup(t *testing.T) {
	_, err := NewCloudWatchAudit(&fakeCloudWatchLogsClient{}, "")
	if !errors.Is(err, ErrLogGroupRequired) {
		t.Fatalf("NewCloudWatchAudit() error = %v, want ErrLogGroupRequired", err)
	}
}

func TestRecordEmitsJSONEncodedAuditEvent(t *testing.T) {
	fake := &fakeCloudWatchLogsClient{}
	auditSink, err := NewCloudWatchAudit(fake, "postern-audit")
	if err != nil {
		t.Fatalf("NewCloudWatchAudit() error = %v", err)
	}

	timestamp := time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	event := broker.AuditEvent{
		Timestamp:     timestamp,
		Event:         "ssh_cert_issued",
		EngineerSub:   "engineer-1234",
		EngineerEmail: "engineer@example.com",
		DeviceSerial:  "SERIAL123",
		PrincipalType: "operator",
		CertSerial:    "42",
		IssuedAt:      timestamp.Unix(),
	}
	if err := auditSink.Record(context.Background(), event); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("PutLogEvents calls = %d, want %d", got, want)
	}
	call := fake.calls[0]
	if got, want := *call.LogGroupName, "postern-audit"; got != want {
		t.Fatalf("log group = %q, want %q", got, want)
	}
	if got, want := *call.LogStreamName, "ssh-cert-issued"; got != want {
		t.Fatalf("log stream = %q, want %q", got, want)
	}
	if got, want := len(call.LogEvents), 1; got != want {
		t.Fatalf("log events = %d, want %d", got, want)
	}
	if got, want := *call.LogEvents[0].Timestamp, timestamp.UnixMilli(); got != want {
		t.Fatalf("log event timestamp = %d, want %d", got, want)
	}

	var roundTripped broker.AuditEvent
	if err := json.Unmarshal([]byte(*call.LogEvents[0].Message), &roundTripped); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got, want := roundTripped.EngineerSub, "engineer-1234"; got != want {
		t.Fatalf("engineer_sub = %q, want %q", got, want)
	}
	if got, want := roundTripped.DeviceSerial, "SERIAL123"; got != want {
		t.Fatalf("device_serial = %q, want %q", got, want)
	}
}

// TestRecordDefaultsTimestampWhenZero locks the contract that callers may emit
// AuditEvents without setting Timestamp; the sink fills "now" so CloudWatch
// always sees a populated value. Don't delete: CloudWatch's PutLogEvents API
// rejects events with timestamp 0.
func TestRecordDefaultsTimestampWhenZero(t *testing.T) {
	fake := &fakeCloudWatchLogsClient{}
	auditSink, err := NewCloudWatchAudit(fake, "postern-audit")
	if err != nil {
		t.Fatalf("NewCloudWatchAudit() error = %v", err)
	}

	before := time.Now().UnixMilli()
	if err := auditSink.Record(context.Background(), broker.AuditEvent{Event: "ssh_cert_issued"}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	after := time.Now().UnixMilli()

	got := *fake.calls[0].LogEvents[0].Timestamp
	if got < before || got > after {
		t.Fatalf("auto-filled timestamp = %d, want within [%d,%d]", got, before, after)
	}
}

func TestRecordPropagatesPutLogEventsError(t *testing.T) {
	want := errors.New("cloudwatch is unavailable")
	fake := &fakeCloudWatchLogsClient{err: want}
	auditSink, err := NewCloudWatchAudit(fake, "postern-audit")
	if err != nil {
		t.Fatalf("NewCloudWatchAudit() error = %v", err)
	}

	err = auditSink.Record(context.Background(), broker.AuditEvent{Event: "ssh_cert_issued"})
	if !errors.Is(err, want) {
		t.Fatalf("Record() error = %v, want errors.Is(%v)", err, want)
	}
	if !strings.Contains(err.Error(), "audit:") {
		t.Fatalf("Record() error = %q, want audit: prefix", err.Error())
	}
}

// TestRecordReportsMissingLogStream asserts the missing-stream error shape.
// CloudWatch returns ResourceNotFoundException when the configured log stream
// doesn't exist; rather than propagating the raw AWS error, Record must wrap
// it in a message naming both the stream and the log group, plus pointing at
// Terraform/IaC as the provisioning surface. Provisioning the stream is an
// operator concern, not something the broker auto-creates at runtime.
func TestRecordReportsMissingLogStream(t *testing.T) {
	fake := &fakeCloudWatchLogsClient{err: &types.ResourceNotFoundException{Message: aws.String("stream missing")}}
	auditSink, err := NewCloudWatchAudit(fake, "postern-audit")
	if err != nil {
		t.Fatalf("NewCloudWatchAudit() error = %v", err)
	}

	err = auditSink.Record(context.Background(), broker.AuditEvent{Event: "ssh_cert_issued"})
	if err == nil {
		t.Fatal("Record() returned nil error, want ResourceNotFoundException-derived error")
	}
	var notFound *types.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		t.Fatalf("Record() error = %v, want errors.As to *ResourceNotFoundException", err)
	}
	message := err.Error()
	if !strings.Contains(message, "ssh-cert-issued") {
		t.Fatalf("Record() error = %q, want stream name", message)
	}
	if !strings.Contains(message, "postern-audit") {
		t.Fatalf("Record() error = %q, want log group name", message)
	}
	if !strings.Contains(message, "Terraform") {
		t.Fatalf("Record() error = %q, want Terraform provisioning hint", message)
	}
}

// TestRecordIgnoresCallerCancellation pins the audit-coverage invariant
// against client-disconnect denial-of-audit: every broker request must
// produce exactly one audit row, even when the engineer's HTTP
// connection is canceled mid-request. CloudWatchAudit.Record detaches
// the caller's context (context.WithoutCancel) and bounds the emit by a
// timeout; the cancellation must NOT propagate to PutLogEvents.
func TestRecordIgnoresCallerCancellation(t *testing.T) {
	fake := &fakeCloudWatchLogsClient{}
	auditSink, err := NewCloudWatchAudit(fake, "postern-audit")
	if err != nil {
		t.Fatalf("NewCloudWatchAudit() error = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel: simulates a client that disconnected before
	// the deferred audit emit ran.

	if err := auditSink.Record(canceled, broker.AuditEvent{Event: "ssh_cert_denied"}); err != nil {
		t.Fatalf("Record() error = %v, want nil even though caller ctx was canceled", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("PutLogEvents call count = %d, want 1 (caller-cancellation must not drop the audit row)", len(fake.calls))
	}
	if fake.observedErrAtCall != nil {
		t.Fatalf("PutLogEvents observed ctx.Err() = %v at call time, want nil (caller cancellation must be detached)", fake.observedErrAtCall)
	}
	if !fake.observedHadDeadline {
		t.Fatal("PutLogEvents observed ctx has no deadline; expected audit-emit timeout bound")
	}
}

type fakeCloudWatchLogsClient struct {
	calls               []*cloudwatchlogs.PutLogEventsInput
	observedErrAtCall   error
	observedHadDeadline bool
	err                 error
}

func (c *fakeCloudWatchLogsClient) PutLogEvents(ctx context.Context, input *cloudwatchlogs.PutLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	c.calls = append(c.calls, input)
	c.observedErrAtCall = ctx.Err()
	_, c.observedHadDeadline = ctx.Deadline()
	if c.err != nil {
		return nil, c.err
	}
	return &cloudwatchlogs.PutLogEventsOutput{}, nil
}
