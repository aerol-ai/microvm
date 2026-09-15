package secrets

import (
	"context"
	"reflect"
	"testing"
)

func TestProviderContextHintsAreNormalizedAndCopied(t *testing.T) {
	incCtx := ContextWithIncarnationID(nil, " inc-1 ")
	if got := IncarnationIDFromContext(incCtx); got != "inc-1" {
		t.Fatalf("incarnation = %q", got)
	}
	if got := IncarnationIDFromContext(nil); got != "" {
		t.Fatalf("nil-context incarnation = %q", got)
	}

	outboxCtx := ContextWithPutOutbox(nil, " inc-2 ", []string{" peer-b ", "peer-a", "peer-a", ""})
	incarnation, recipients, ok := PutOutboxFromContext(outboxCtx)
	if !ok || incarnation != "inc-2" || !reflect.DeepEqual(recipients, []string{"peer-a", "peer-b"}) {
		t.Fatalf("put-outbox hint = %q %v %v", incarnation, recipients, ok)
	}
	recipients[0] = "mutated"
	_, again, _ := PutOutboxFromContext(outboxCtx)
	if !reflect.DeepEqual(again, []string{"peer-a", "peer-b"}) {
		t.Fatalf("stored put-outbox recipients were aliased: %v", again)
	}
	if _, _, ok := PutOutboxFromContext(nil); ok {
		t.Fatal("nil context unexpectedly carried put-outbox hint")
	}
	if _, _, ok := PutOutboxFromContext(context.Background()); ok {
		t.Fatal("plain context unexpectedly carried put-outbox hint")
	}

	retiredCtx := ContextWithRetiredRecipients(nil, []string{" peer-b ", "peer-a", "peer-a"})
	retired, ok := RetiredRecipientsFromContext(retiredCtx)
	if !ok || !reflect.DeepEqual(retired, []string{"peer-a", "peer-b"}) {
		t.Fatalf("retired recipients = %v %v", retired, ok)
	}
	retired[0] = "mutated"
	again, _ = RetiredRecipientsFromContext(retiredCtx)
	if !reflect.DeepEqual(again, []string{"peer-a", "peer-b"}) {
		t.Fatalf("stored retired recipients were aliased: %v", again)
	}
	if _, ok := RetiredRecipientsFromContext(nil); ok {
		t.Fatal("nil context unexpectedly carried retired recipients")
	}
	if _, ok := RetiredRecipientsFromContext(context.Background()); ok {
		t.Fatal("plain context unexpectedly carried retired recipients")
	}
}
