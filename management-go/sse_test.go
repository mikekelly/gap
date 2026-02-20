package gap

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeSSEResponse wraps a string body in a minimal *http.Response so
// newEventStream can be used without a real HTTP server.
func fakeSSEResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// testEvent is a simple struct used across SSE unit tests.
type testEvent struct {
	Msg string `json:"msg"`
	Num int    `json:"num"`
}

// TestSSE_BasicParsing verifies that a single well-formed SSE event is
// decoded into the target type correctly.
func TestSSE_BasicParsing(t *testing.T) {
	body := "data: {\"msg\":\"hello\",\"num\":42}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	evt, err := stream.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.Msg != "hello" {
		t.Errorf("Msg: got %q, want %q", evt.Msg, "hello")
	}
	if evt.Num != 42 {
		t.Errorf("Num: got %d, want %d", evt.Num, 42)
	}
}

// TestSSE_MultiLineData verifies that multiple consecutive data: lines are
// joined with a newline and decoded together (rare but valid per the SSE spec).
func TestSSE_MultiLineData(t *testing.T) {
	// The SSE spec allows splitting data across multiple "data:" lines;
	// they are joined with \n before parsing.
	body := "data: {\"msg\":\"split\",\n" +
		"data: \"num\":7}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	evt, err := stream.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.Msg != "split" {
		t.Errorf("Msg: got %q, want %q", evt.Msg, "split")
	}
	if evt.Num != 7 {
		t.Errorf("Num: got %d, want %d", evt.Num, 7)
	}
}

// TestSSE_CommentsIgnored verifies that lines starting with ":" (SSE comments)
// are silently skipped and do not affect event parsing.
func TestSSE_CommentsIgnored(t *testing.T) {
	body := ": this is a comment\ndata: {\"msg\":\"ok\",\"num\":1}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	evt, err := stream.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.Msg != "ok" {
		t.Errorf("Msg: got %q, want %q", evt.Msg, "ok")
	}
}

// TestSSE_EmptyEventsSkipped verifies that blank lines without any data lines
// (heartbeat/keep-alive frames) do not produce events; the parser continues
// scanning until real data arrives.
func TestSSE_EmptyEventsSkipped(t *testing.T) {
	// First "event" is just a blank line (heartbeat), second has actual data.
	body := "\n\ndata: {\"msg\":\"real\",\"num\":2}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	evt, err := stream.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.Msg != "real" {
		t.Errorf("Msg: got %q, want %q", evt.Msg, "real")
	}
}

// TestSSE_EventTypeFieldIgnored verifies that an "event:" field does not
// interfere with data parsing; the library uses data lines only.
func TestSSE_EventTypeFieldIgnored(t *testing.T) {
	body := "event: update\ndata: {\"msg\":\"typed\",\"num\":3}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	evt, err := stream.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.Msg != "typed" {
		t.Errorf("Msg: got %q, want %q", evt.Msg, "typed")
	}
}

// TestSSE_EOF verifies that Next() returns io.EOF once the body is exhausted.
func TestSSE_EOF(t *testing.T) {
	body := "data: {\"msg\":\"last\",\"num\":0}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	// Consume the one event.
	if _, err := stream.Next(); err != nil {
		t.Fatalf("unexpected error on first Next: %v", err)
	}

	// Second call should return io.EOF.
	_, err := stream.Next()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

// TestSSE_MultipleEvents verifies that a stream with multiple events returns
// them in order and then returns io.EOF.
func TestSSE_MultipleEvents(t *testing.T) {
	body := "data: {\"msg\":\"a\",\"num\":1}\n\n" +
		"data: {\"msg\":\"b\",\"num\":2}\n\n" +
		"data: {\"msg\":\"c\",\"num\":3}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	want := []testEvent{
		{Msg: "a", Num: 1},
		{Msg: "b", Num: 2},
		{Msg: "c", Num: 3},
	}

	for i, w := range want {
		evt, err := stream.Next()
		if err != nil {
			t.Fatalf("event %d: unexpected error: %v", i, err)
		}
		if evt != w {
			t.Errorf("event %d: got %+v, want %+v", i, evt, w)
		}
	}

	_, err := stream.Next()
	if err != io.EOF {
		t.Errorf("expected io.EOF after last event, got %v", err)
	}
}

// TestSSE_InvalidJSON verifies that malformed JSON in a data field returns an
// error rather than panicking, and that the error is descriptive.
func TestSSE_InvalidJSON(t *testing.T) {
	body := "data: not-valid-json\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))
	defer stream.Close()

	_, err := stream.Next()
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestSSE_CloseStopsParsing verifies that calling Close() marks the stream as
// done so that subsequent calls to Next() return io.EOF immediately without
// reading further from the body.
func TestSSE_CloseStopsParsing(t *testing.T) {
	// Stream has valid data but we close before reading.
	body := "data: {\"msg\":\"never\",\"num\":0}\n\n"
	stream := newEventStream[testEvent](fakeSSEResponse(body))

	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	_, err := stream.Next()
	if err != io.EOF {
		t.Errorf("expected io.EOF after Close, got %v", err)
	}
}
