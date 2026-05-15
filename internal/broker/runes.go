package broker

import "unicode/utf8"

// TruncateRunes caps s at limit runes (NOT bytes) — drops trailing runes
// rather than slicing bytes, which would risk splitting a multi-byte
// codepoint and producing invalid UTF-8. Used at every engineer-influenced
// input boundary the broker pipeline accepts (HTTP handlers cap UserAgent,
// device_id, etc.) so downstream sinks (CloudWatch's 256KB-per-event
// limit, DynamoDB's 2KB partition-key cap) never receive a value larger
// than the broker promised them.
func TruncateRunes(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}
