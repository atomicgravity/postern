// Package audit is the broker's AuditSink impl: writes AuditEvent records as
// JSON to a fixed CloudWatch log stream inside the configured log group. The
// log group and stream are operator-provisioned via Terraform; the sink does
// not auto-create AWS resources.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

const auditLogStreamName = "ssh-cert-issued"

// auditEmitTimeout caps a single PutLogEvents call so a misbehaving CloudWatch
// client can't wedge the broker. The detached context (see Record) means a
// stuck goroutine here cannot DoS engineer requests, but bounding is still
// belt-and-suspenders.
const auditEmitTimeout = 5 * time.Second

// ErrLogGroupRequired is returned by NewCloudWatchAudit when the log group is
// empty.
var ErrLogGroupRequired = errors.New("CloudWatch log group is required")

// CloudWatchLogsClient is the subset of the CloudWatch Logs API the audit
// sink consumes.
type CloudWatchLogsClient interface {
	PutLogEvents(context.Context, *cloudwatchlogs.PutLogEventsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
}

// CloudWatchAudit writes audit events to a fixed "ssh-cert-issued" log
// stream inside the configured CloudWatch log group.
type CloudWatchAudit struct {
	client   CloudWatchLogsClient
	logGroup string
}

// NewCloudWatchAudit constructs an Audit sink writing to "ssh-cert-issued"
// inside the supplied log group. The log group and stream must already
// exist — the sink does not auto-create AWS resources. On a missing stream
// Record returns an error naming both group and stream so operators can
// diagnose without parsing raw AWS-SDK error text.
func NewCloudWatchAudit(client CloudWatchLogsClient, logGroup string) (*CloudWatchAudit, error) {
	if logGroup == "" {
		return nil, ErrLogGroupRequired
	}
	return &CloudWatchAudit{client: client, logGroup: logGroup}, nil
}

// NewCloudWatchAuditFromConfig wires the CloudWatch Logs client from an
// aws.Config and delegates to NewCloudWatchAudit.
func NewCloudWatchAuditFromConfig(config aws.Config, logGroup string) (*CloudWatchAudit, error) {
	return NewCloudWatchAudit(cloudwatchlogs.NewFromConfig(config), logGroup)
}

// Record writes one audit event to CloudWatch Logs.
//
// ctx is detached via context.WithoutCancel and bounded by auditEmitTimeout
// before the AWS call. The audit-coverage invariant — every broker request
// produces exactly one audit row — must not be defeatable by client-side
// disconnect: a TCP-RST after a 4xx codepath would otherwise cancel ctx,
// PutLogEvents would return context.Canceled, and the audit row would be
// lost. The detach preserves request values but drops cancellation.
func (a *CloudWatchAudit) Record(ctx context.Context, event broker.AuditEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	timestamp := event.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditEmitTimeout)
	defer cancel()

	_, err = a.client.PutLogEvents(emitCtx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String(a.logGroup),
		LogStreamName: aws.String(auditLogStreamName),
		LogEvents: []types.InputLogEvent{{
			Message:   aws.String(string(encoded)),
			Timestamp: aws.Int64(timestamp.UnixMilli()),
		}},
	})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return fmt.Errorf("audit log stream %q in group %q does not exist; create via Terraform/IaC before running broker: %w", auditLogStreamName, a.logGroup, err)
		}
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}
