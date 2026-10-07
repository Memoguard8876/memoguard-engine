package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	rules "github.com/memoguard8876/memoguard-rules"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
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
	t.Helper()
	account := txnbuild.NewSimpleAccount(keypair.MustRandom().Address(), 1)
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount: &account, IncrementSequenceNum: true,
		Operations: []txnbuild.Operation{&txnbuild.ManageData{Name: "reference", Value: value}},
		BaseFee:    txnbuild.MinBaseFee, Memo: txnbuild.MemoText(memo),
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
