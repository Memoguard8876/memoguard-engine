package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	rules "github.com/memoguard8876/memoguard-rules"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func testScanner(t *testing.T) *Scanner {
	t.Helper()
	scanner, err := New(rules.Default())
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func testEnvelope(t *testing.T, memo string, value []byte) string {
	return testEnvelopeWithMemo(t, txnbuild.MemoText(memo), value)
}

func testEnvelopeWithMemo(t *testing.T, memo txnbuild.Memo, value []byte) string {
	t.Helper()
	account := txnbuild.NewSimpleAccount(keypair.MustRandom().Address(), 1)
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount: &account, IncrementSequenceNum: true,
		Operations: []txnbuild.Operation{&txnbuild.ManageData{Name: "reference", Value: value}},
		BaseFee:    txnbuild.MinBaseFee, Memo: memo,
		Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatal(err)
	}
	xdr, err := tx.Base64()
	if err != nil {
		t.Fatal(err)
	}
	return xdr
}

func TestNumericAndPrintableBinaryMemos(t *testing.T) {
	policy := rules.Default()
	policy.Rules = append(policy.Rules, rules.Rule{
		ID: "configured.customer_id", Description: "Synthetic customer ID",
		Remediation: "Use an opaque reference", Pattern: `\b123456789\b`,
		Scopes: []string{"transaction.memo.id"}, Severity: rules.Block, Confidence: rules.High,
	})
	scanner, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	var hash txnbuild.MemoHash
	for i := range hash {
		hash[i] = ' '
	}
	copy(hash[:], "person@example.com")
	var returnHash txnbuild.MemoReturn
	copy(returnHash[:], hash[:])
	for _, test := range []struct {
		name string
		memo txnbuild.Memo
		path string
	}{
		{"id", txnbuild.MemoID(123456789), "transaction.memo.id"},
		{"hash", hash, "transaction.memo.hash"},
		{"return", returnHash, "transaction.memo.return"},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope := testEnvelopeWithMemo(t, test.memo, []byte("reference"))
			report, err := scanner.Scan(context.Background(), Input{Kind: EnvelopeXDR, Payload: []byte(envelope)})
			if err != nil || len(report.Findings) != 1 || report.Findings[0].FieldPath != test.path {
				t.Fatalf("report=%#v err=%v", report, err)
			}
		})
	}
}

func FuzzMalformedInputDoesNotPanic(f *testing.F) {
	f.Add([]byte("not-base64"))
	f.Add([]byte(`{"memo":{"text":"reference"}}`))
	scanner, err := New(rules.Default())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > MaxInputBytes {
			return
		}
		for _, kind := range []Kind{EnvelopeXDR, DecodedJSON, SorobanSimulation} {
			_, _ = scanner.Scan(context.Background(), Input{Kind: kind, Payload: data})
		}
	})
}

func TestSimulationResultAndEventAreRedacted(t *testing.T) {
	value, err := xdr.NewScVal(xdr.ScValTypeScvString, xdr.ScString("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	encodedValue, err := xdr.MarshalBase64(value)
	if err != nil {
		t.Fatal(err)
	}
	body, err := xdr.NewContractEventBody(0, xdr.ContractEventV0{Topics: []xdr.ScVal{value}, Data: value})
	if err != nil {
		t.Fatal(err)
	}
	event := xdr.DiagnosticEvent{Event: xdr.ContractEvent{Body: body}}
	encodedEvent, err := xdr.MarshalBase64(event)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{"events": []string{encodedEvent}, "results": []map[string]string{{"xdr": encodedValue}}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := testScanner(t).Scan(context.Background(), Input{Kind: SorobanSimulation, Payload: input})
	if err != nil || len(report.Findings) != 3 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	output, err := json.Marshal(report)
	if err != nil || strings.Contains(string(output), "person@example.com") {
		t.Fatalf("unsafe report: %v", err)
	}
}

func TestStoredSyntheticXDRFixtures(t *testing.T) {
	for _, test := range []struct {
		name, wantPath string
	}{
		{"clean.xdr", ""},
		{"unsafe-email.xdr", "transaction.memo.text"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + test.name)
			if err != nil {
				t.Fatal(err)
			}
			report, err := testScanner(t).Scan(context.Background(), Input{Kind: EnvelopeXDR, Payload: data})
			if err != nil {
				t.Fatal(err)
			}
			if test.wantPath == "" && len(report.Findings) == 0 {
				return
			}
			if len(report.Findings) != 1 || report.Findings[0].FieldPath != test.wantPath {
				t.Fatalf("unexpected findings: %#v", report.Findings)
			}
		})
	}
}

func TestExtractionLimitsFailClosed(t *testing.T) {
	for _, input := range []string{
		strings.Repeat(`{"a":`, maxDepth+1) + `"safe"` + strings.Repeat("}", maxDepth+1),
		`{"value":"` + strings.Repeat("a", maxTextBytes+1) + `"}`,
		`["a",` + strings.Repeat(`"a",`, maxFields-1) + `"a"]`,
	} {
		report, err := testScanner(t).Scan(context.Background(), Input{Kind: DecodedJSON, Payload: []byte(input)})
		if !errors.Is(err, errExtractionLimit) || len(report.Findings) != 0 {
			t.Fatalf("expected incomplete-scan error, got report=%#v err=%v", report, err)
		}
	}
}

func TestDecodedJSONPreservesNumericIDs(t *testing.T) {
	policy := rules.Default()
	policy.Rules = append(policy.Rules, rules.Rule{ID: "configured.id", Description: "Synthetic numeric ID", Remediation: "Use an opaque reference", Pattern: `\b123456789\b`, Scopes: []string{"transaction.customer_id"}, Severity: rules.Block, Confidence: rules.High})
	scanner, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.Scan(context.Background(), Input{Kind: DecodedJSON, Payload: []byte(`{"customer_id":123456789}`)})
	if err != nil || len(report.Findings) != 1 || report.Findings[0].FieldPath != "transaction.customer_id" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func TestEnvelopeFindsEmailWithoutExposingIt(t *testing.T) {
	secret := "person@example.com"
	xdr := testEnvelope(t, secret, []byte("opaque-reference"))
	report, err := testScanner(t).Scan(context.Background(), Input{Kind: EnvelopeXDR, Payload: []byte(xdr)})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].FieldPath != "transaction.memo.text" || !report.Blocked() {
		t.Fatalf("unexpected finding: %#v", report)
	}
	serialized, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), secret) {
		t.Fatal("report disclosed matched content")
	}
}

func TestEnvelopeFindsManageDataValue(t *testing.T) {
	xdr := testEnvelope(t, "reference", []byte("person@example.com"))
	report, err := testScanner(t).Scan(context.Background(), Input{Kind: EnvelopeXDR, Payload: []byte(xdr)})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].FieldPath != "transaction.operations.0.manage_data.value" {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
}

func TestMalformedEnvelopeIsControlledError(t *testing.T) {
	_, err := testScanner(t).Scan(context.Background(), Input{Kind: EnvelopeXDR, Payload: []byte("not-base64")})
	if err == nil || strings.Contains(err.Error(), "not-base64") {
		t.Fatalf("unsafe parsing error: %v", err)
	}
}

func TestExceptionOnlySuppressesOneField(t *testing.T) {
	policy := rules.Default()
	policy.Exceptions = []rules.Exception{{RuleID: "personal.email", FieldPath: "transaction.memo.text", Reason: "public inbox", ExpiresAt: time.Now().Add(time.Hour)}}
	scanner, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.Scan(context.Background(), Input{Kind: DecodedJSON, Payload: []byte(`{"memo":{"text":"public@example.com"},"other":"private@example.com"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].FieldPath != "transaction.other" {
		t.Fatalf("exception widened unexpectedly: %#v", report.Findings)
	}
}
