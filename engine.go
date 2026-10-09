package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	rules "github.com/memoguard8876/memoguard-rules"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const MaxInputBytes = 2 << 20
const maxFields = 4096
const maxDepth = 12
const maxTextBytes = 64 << 10

var errExtractionLimit = errors.New("supported input exceeds scan depth, field, or text limit")

type Kind string

const (
	EnvelopeXDR       Kind = "envelope_xdr"
	MemoText          Kind = "memo_text"
	SorobanSimulation Kind = "soroban_simulation"
	DecodedJSON       Kind = "decoded_json"
)

type Input struct {
	Kind    Kind
	Payload []byte
}

type Finding struct {
	RuleID      string           `json:"rule_id"`
	Severity    rules.Severity   `json:"severity"`
	Confidence  rules.Confidence `json:"confidence"`
	FieldPath   string           `json:"field_path"`
	Description string           `json:"description"`
	Remediation string           `json:"remediation"`
}

type Report struct {
	PolicyVersion string    `json:"policy_version"`
	Findings      []Finding `json:"findings"`
}

func (r Report) Blocked() bool {
	for _, finding := range r.Findings {
		if finding.Severity == rules.Block {
			return true
		}
	}
	return false
}

type field struct {
	path  string
	value string
}

type Scanner struct {
	policy   rules.Policy
	patterns map[string]*regexp.Regexp
	now      func() time.Time
}

func New(policy rules.Policy) (*Scanner, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	patterns := make(map[string]*regexp.Regexp, len(policy.Rules))
	for _, rule := range policy.Rules {
		patterns[rule.ID] = regexp.MustCompile(rule.Pattern)
	}
	return &Scanner{policy: policy, patterns: patterns, now: time.Now}, nil
}

func (s *Scanner) Scan(ctx context.Context, input Input) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if len(input.Payload) == 0 || len(input.Payload) > MaxInputBytes {
		return Report{}, fmt.Errorf("input must contain 1 to %d bytes", MaxInputBytes)
	}
	fields, err := extract(input)
	if err != nil {
		return Report{}, err
	}
	report := Report{PolicyVersion: s.policy.Version, Findings: []Finding{}}
	now := s.now()
	for _, f := range fields {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		for _, rule := range s.policy.Rules {
			if !applies(rule.Scopes, f.path) || s.policy.IsExcepted(rule.ID, f.path, now) {
				continue
			}
			if s.patterns[rule.ID].MatchString(f.value) {
				report.Findings = append(report.Findings, Finding{
					RuleID: rule.ID, Severity: rule.Severity, Confidence: rule.Confidence,
					FieldPath: f.path, Description: rule.Description, Remediation: rule.Remediation,
				})
			}
		}
	}
	return report, nil
}

func applies(scopes []string, path string) bool {
	for _, scope := range scopes {
		if rules.MatchesScope(scope, path) {
			return true
		}
	}
	return false
}

func extract(input Input) ([]field, error) {
	switch input.Kind {
	case MemoText:
		return []field{{path: "transaction.memo.text", value: string(input.Payload)}}, nil
	case EnvelopeXDR:
		return extractEnvelope(strings.TrimSpace(string(input.Payload)))
	case SorobanSimulation:
		return extractSimulation(input.Payload)
	case DecodedJSON:
		return extractJSON(input.Payload)
	default:
		return nil, fmt.Errorf("unsupported input kind %q", input.Kind)
	}
}

func extractEnvelope(encoded string) ([]field, error) {
	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(encoded, &envelope); err != nil {
		return nil, errors.New("invalid transaction envelope XDR")
	}
	if envelope.Type != xdr.EnvelopeTypeEnvelopeTypeTx && envelope.Type != xdr.EnvelopeTypeEnvelopeTypeTxV0 && envelope.Type != xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
		return nil, errors.New("unsupported transaction envelope type")
	}
	fields := make([]field, 0, 8)
	if text, ok := envelope.Memo().GetText(); ok {
		fields = append(fields, field{path: "transaction.memo.text", value: text})
	}
	if id, ok := envelope.Memo().GetId(); ok {
		fields = append(fields, field{path: "transaction.memo.id", value: fmt.Sprint(uint64(id))})
	}
	if hash, ok := envelope.Memo().GetHash(); ok {
		if err := appendText(&fields, "transaction.memo.hash", hash[:]); err != nil {
			return nil, err
		}
	}
	if hash, ok := envelope.Memo().GetRetHash(); ok {
		if err := appendText(&fields, "transaction.memo.return", hash[:]); err != nil {
			return nil, err
		}
	}
	for i, op := range envelope.Operations() {
		base := fmt.Sprintf("transaction.operations.%d", i)
		if data, ok := op.Body.GetManageDataOp(); ok {
			fields = append(fields, field{path: base + ".manage_data.name", value: string(data.DataName)})
			if data.DataValue != nil {
				if err := appendText(&fields, base+".manage_data.value", []byte(*data.DataValue)); err != nil {
					return nil, err
				}
			}
		}
		if options, ok := op.Body.GetSetOptionsOp(); ok && options.HomeDomain != nil {
			fields = append(fields, field{path: base + ".set_options.home_domain", value: string(*options.HomeDomain)})
		}
		if invoke, ok := op.Body.GetInvokeHostFunctionOp(); ok {
			if args, ok := invoke.HostFunction.GetInvokeContract(); ok {
				for j, arg := range args.Args {
					if err := appendSCVal(&fields, fmt.Sprintf("%s.invoke_contract.args.%d", base, j), arg, 0); err != nil {
						return nil, err
					}
				}
			}
			if args, ok := invoke.HostFunction.GetCreateContractV2(); ok {
				for j, arg := range args.ConstructorArgs {
					if err := appendSCVal(&fields, fmt.Sprintf("%s.create_contract.constructor_args.%d", base, j), arg, 0); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return fields, nil
}

func appendSCVal(fields *[]field, path string, value xdr.ScVal, depth int) error {
	if depth > maxDepth || len(*fields) >= maxFields {
		return errExtractionLimit
	}
	if text, ok := value.GetStr(); ok {
		return appendText(fields, path, []byte(text))
	}
	if text, ok := value.GetSym(); ok {
		return appendText(fields, path, []byte(text))
	}
	if bytes, ok := value.GetBytes(); ok {
		return appendText(fields, path, []byte(bytes))
	}
	if vec, ok := value.GetVec(); ok && vec != nil {
		for i, item := range *vec {
			if err := appendSCVal(fields, fmt.Sprintf("%s.vec.%d", path, i), item, depth+1); err != nil {
				return err
			}
		}
	}
	if entries, ok := value.GetMap(); ok && entries != nil {
		for i, entry := range *entries {
			if err := appendSCVal(fields, fmt.Sprintf("%s.map.%d.key", path, i), entry.Key, depth+1); err != nil {
				return err
			}
			if err := appendSCVal(fields, fmt.Sprintf("%s.map.%d.value", path, i), entry.Val, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendText(fields *[]field, path string, data []byte) error {
	if len(data) > maxTextBytes || len(*fields) >= maxFields {
		return errExtractionLimit
	}
	if len(data) == 0 || !utf8.Valid(data) {
		return nil
	}
	for _, r := range string(data) {
		if r < 0x20 && r != '\n' && r != '\t' {
			return nil
		}
	}
	*fields = append(*fields, field{path: path, value: string(data)})
	return nil
}

type simulation struct {
	Error   string   `json:"error"`
	Events  []string `json:"events"`
	Results []struct {
		XDR *string `json:"xdr"`
	} `json:"results"`
}

// simulationKeys are the members a simulateTransaction result can carry. A
// document with none of them is not recognizable as simulation output.
var simulationKeys = []string{"events", "results", "error", "latestLedger", "transactionData", "minResourceFee", "restorePreamble", "stateChanges", "cost"}

// simulationPayload returns the simulation result object. It accepts the bare
// result object and a full JSON-RPC reply that wraps it in "result". Anything
// else fails closed rather than scanning nothing.
func simulationPayload(data []byte) ([]byte, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, errors.New("invalid simulation JSON")
	}
	if _, rpc := members["jsonrpc"]; rpc || members["result"] != nil {
		wrapped, ok := members["result"]
		if !ok {
			return nil, errors.New("simulation request failed")
		}
		data = wrapped
		members = nil
		if err := json.Unmarshal(data, &members); err != nil {
			return nil, errors.New("invalid simulation JSON")
		}
	}
	for _, key := range simulationKeys {
		if _, ok := members[key]; ok {
			return data, nil
		}
	}
	return nil, errors.New("unrecognized simulation JSON")
}

func extractSimulation(data []byte) ([]field, error) {
	data, err := simulationPayload(data)
	if err != nil {
		return nil, err
	}
	var result simulation
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, errors.New("invalid simulation JSON")
	}
	if result.Error != "" {
		return nil, errors.New("simulation reported an error")
	}
	fields := make([]field, 0, 8)
	for i, encoded := range result.Events {
		var event xdr.DiagnosticEvent
		if err := xdr.SafeUnmarshalBase64(encoded, &event); err != nil {
			return nil, fmt.Errorf("invalid simulation event %d XDR", i)
		}
		if body, ok := event.Event.Body.GetV0(); ok {
			for j, topic := range body.Topics {
				if err := appendSCVal(&fields, fmt.Sprintf("simulation.events.%d.topics.%d", i, j), topic, 0); err != nil {
					return nil, err
				}
			}
			if err := appendSCVal(&fields, fmt.Sprintf("simulation.events.%d.data", i), body.Data, 0); err != nil {
				return nil, err
			}
		}
	}
	for i, item := range result.Results {
		if item.XDR == nil {
			continue
		}
		var value xdr.ScVal
		if err := xdr.SafeUnmarshalBase64(*item.XDR, &value); err != nil {
			return nil, fmt.Errorf("invalid simulation result %d XDR", i)
		}
		if err := appendSCVal(&fields, fmt.Sprintf("simulation.results.%d.return_value", i), value, 0); err != nil {
			return nil, err
		}
	}
	return fields, nil
}

func extractJSON(data []byte) ([]field, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid decoded JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("invalid decoded JSON")
	}
	fields := make([]field, 0, 8)
	if err := appendJSON(&fields, "transaction", value, 0); err != nil {
		return nil, err
	}
	return fields, nil
}

func appendJSON(fields *[]field, path string, value any, depth int) error {
	if depth > maxDepth || len(*fields) >= maxFields {
		return errExtractionLimit
	}
	switch typed := value.(type) {
	case string:
		return appendText(fields, path, []byte(typed))
	case json.Number:
		return appendText(fields, path, []byte(typed.String()))
	case []any:
		for i, item := range typed {
			if err := appendJSON(fields, fmt.Sprintf("%s.%d", path, i), item, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := appendJSON(fields, path+"."+key, typed[key], depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
