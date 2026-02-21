// Package vellaveto — validation for types used by the client.
package vellaveto

import (
	"encoding/json"
	"fmt"
)

// maxParametersJSONSize is the maximum serialized size of Parameters (512KB).
// SECURITY (FIND-R101-004): Prevents sending oversized payloads that approach
// the server's MAX_REQUEST_BODY_SIZE (1MB).
const maxParametersJSONSize = 524288

// maxContextFieldLength is the maximum length for SessionID, AgentID, TenantID.
const maxContextFieldLength = 256

// maxCallChainLength is the maximum number of entries in CallChain.
const maxCallChainLength = 100

// maxCallChainEntryLength is the maximum length for each CallChain entry.
const maxCallChainEntryLength = 256

// maxMetadataKeys is the maximum number of keys in Metadata.
const maxMetadataKeys = 100

// validateParameters checks that Parameters serialized size is within bounds.
// SECURITY (FIND-R101-004): Prevents oversized payloads approaching the
// server's 1MB body limit.
func validateParameters(params map[string]interface{}) error {
	if len(params) == 0 {
		return nil
	}
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("vellaveto: action.Parameters serialization failed: %w", err)
	}
	if len(paramBytes) > maxParametersJSONSize {
		return fmt.Errorf("vellaveto: action.Parameters exceeds max serialized size %d bytes", maxParametersJSONSize)
	}
	return nil
}

// Validate checks that the EvaluationContext fields are within safe bounds
// and contain no control or Unicode format characters.
// SECURITY (FIND-R101-003): Prevents unbounded context fields from causing
// OOM on the server and rejects invisible-text manipulation characters.
func (ec *EvaluationContext) Validate() error {
	// Validate string identity fields for length, control chars, and format chars.
	fields := [3][2]string{
		{"session_id", ec.SessionID},
		{"agent_id", ec.AgentID},
		{"tenant_id", ec.TenantID},
	}
	for _, pair := range fields {
		name, value := pair[0], pair[1]
		if len(value) > maxContextFieldLength {
			return fmt.Errorf("vellaveto: context.%s exceeds max length %d", name, maxContextFieldLength)
		}
		for _, c := range value {
			if c < ' ' || (c >= 0x7F && c <= 0x9F) {
				return fmt.Errorf("vellaveto: context.%s contains control characters", name)
			}
			if isUnicodeFormatChar(c) {
				return fmt.Errorf("vellaveto: context.%s contains Unicode format characters", name)
			}
		}
	}
	// Validate CallChain bounds.
	if len(ec.CallChain) > maxCallChainLength {
		return fmt.Errorf("vellaveto: context.CallChain has %d entries, max %d", len(ec.CallChain), maxCallChainLength)
	}
	for i, entry := range ec.CallChain {
		if len(entry) > maxCallChainEntryLength {
			return fmt.Errorf("vellaveto: context.CallChain[%d] exceeds max length %d", i, maxCallChainEntryLength)
		}
		// SECURITY (FIND-R114-003): Validate call_chain entries for control
		// and Unicode format characters. Parity with identity field validation
		// (session_id, agent_id, tenant_id) which already checks these.
		for _, c := range entry {
			if c < ' ' || (c >= 0x7F && c <= 0x9F) {
				return fmt.Errorf("vellaveto: context.CallChain[%d] contains control characters", i)
			}
			if isUnicodeFormatChar(c) {
				return fmt.Errorf("vellaveto: context.CallChain[%d] contains Unicode format characters", i)
			}
		}
	}
	// Validate Metadata key count.
	if len(ec.Metadata) > maxMetadataKeys {
		return fmt.Errorf("vellaveto: context.Metadata has %d keys, max %d", len(ec.Metadata), maxMetadataKeys)
	}
	return nil
}
