package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	rules "github.com/memoguard8876/memoguard-rules"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const MaxInputBytes = 2 << 20

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
	for i, op := range envelope.Operations() {
		base := fmt.Sprintf("transaction.operations.%d", i)
		if data, ok := op.Body.GetManageDataOp(); ok {
			fields = append(fields, field{path: base + ".manage_data.name", value: string(data.DataName)})
			if data.DataValue != nil {
				appendText(&fields, base+".manage_data.value", []byte(*data.DataValue))
			}
		}
		if options, ok := op.Body.GetSetOptionsOp(); ok && options.HomeDomain != nil {
			fields = append(fields, field{path: base + ".set_options.home_domain", value: string(*options.HomeDomain)})
		}
		if invoke, ok := op.Body.GetInvokeHostFunctionOp(); ok {
			if args, ok := invoke.HostFunction.GetInvokeContract(); ok {
				for j, arg := range args.Args {
					appendSCVal(&fields, fmt.Sprintf("%s.invoke_contract.args.%d", base, j), arg, 0)
				}
			}
			if args, ok := invoke.HostFunction.GetCreateContractV2(); ok {
				for j, arg := range args.ConstructorArgs {
					appendSCVal(&fields, fmt.Sprintf("%s.create_contract.constructor_args.%d", base, j), arg, 0)
				}
			}
		}
	}
	return fields, nil
}

func appendSCVal(fields *[]field, path string, value xdr.ScVal, depth int) {
	if depth > 12 || len(*fields) > 4096 {
		return
	}
	if text, ok := value.GetStr(); ok {
		appendText(fields, path, []byte(text))
	}
	if text, ok := value.GetSym(); ok {
		appendText(fields, path, []byte(text))
	}
	if bytes, ok := value.GetBytes(); ok {
		appendText(fields, path, []byte(bytes))
	}
	if vec, ok := value.GetVec(); ok && vec != nil {
		for i, item := range *vec {
			appendSCVal(fields, fmt.Sprintf("%s.vec.%d", path, i), item, depth+1)
		}
	}
	if entries, ok := value.GetMap(); ok && entries != nil {
		for i, entry := range *entries {
			appendSCVal(fields, fmt.Sprintf("%s.map.%d.key", path, i), entry.Key, depth+1)
			appendSCVal(fields, fmt.Sprintf("%s.map.%d.value", path, i), entry.Val, depth+1)
		}
	}
}

func appendText(fields *[]field, path string, data []byte) {
	if len(data) == 0 || len(data) > 64<<10 || !utf8.Valid(data) {
		return
	}
	for _, r := range string(data) {
		if r < 0x20 && r != '\n' && r != '\t' {
			return
		}
	}
	*fields = append(*fields, field{path: path, value: string(data)})
}

type simulation struct {
	Error   string   `json:"error"`
	Events  []string `json:"events"`
	Results []struct {
		XDR *string `json:"xdr"`
	} `json:"results"`
}

func extractSimulation(data []byte) ([]field, error) {
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
				appendSCVal(&fields, fmt.Sprintf("simulation.events.%d.topics.%d", i, j), topic, 0)
			}
			appendSCVal(&fields, fmt.Sprintf("simulation.events.%d.data", i), body.Data, 0)
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
		appendSCVal(&fields, fmt.Sprintf("simulation.results.%d.return_value", i), value, 0)
	}
	return fields, nil
}

func extractJSON(data []byte) ([]field, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, errors.New("invalid decoded JSON")
	}
	fields := make([]field, 0, 8)
	appendJSON(&fields, "transaction", value, 0)
	return fields, nil
}

func appendJSON(fields *[]field, path string, value any, depth int) {
	if depth > 12 || len(*fields) > 4096 {
		return
	}
	switch typed := value.(type) {
	case string:
		appendText(fields, path, []byte(typed))
	case []any:
		for i, item := range typed {
			appendJSON(fields, fmt.Sprintf("%s.%d", path, i), item, depth+1)
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			appendJSON(fields, path+"."+key, typed[key], depth+1)
		}
	}
}
