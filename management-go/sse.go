package gap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// EventStream reads Server-Sent Events from an HTTP response and deserializes
// each event's data field into type T.
//
// Usage:
//
//	stream, err := client.SomeSSEMethod(ctx)
//	if err != nil { ... }
//	defer stream.Close()
//	for {
//	    entry, err := stream.Next()
//	    if err == io.EOF { break }
//	    if err != nil { ... }
//	    // use entry
//	}
type EventStream[T any] struct {
	resp    *http.Response
	scanner *bufio.Scanner
	done    bool
}

// newEventStream wraps an SSE HTTP response in an EventStream.
func newEventStream[T any](resp *http.Response) *EventStream[T] {
	s := &EventStream[T]{
		resp:    resp,
		scanner: bufio.NewScanner(resp.Body),
	}
	s.scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	return s
}

// Next blocks until the next complete SSE event is received, then deserializes
// the data field into T and returns it.
// Returns io.EOF when the stream ends cleanly.
// Returns an error if the stream is already done, or if parsing/deserialization fails.
func (s *EventStream[T]) Next() (T, error) {
	var zero T
	if s.done {
		return zero, io.EOF
	}

	// Accumulate fields for one SSE event (delimited by an empty line).
	var dataLines []string

	for s.scanner.Scan() {
		line := s.scanner.Text()

		switch {
		case strings.HasPrefix(line, "data: "):
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))

		case strings.HasPrefix(line, ":"):
			// Comment — skip.

		case strings.HasPrefix(line, "event:"):
			// Event type — we note but don't gate on it; data drives dispatch.

		case strings.HasPrefix(line, "id:"):
			// Event ID — ignore for now.

		case strings.HasPrefix(line, "retry:"):
			// Reconnect hint — ignore.

		case line == "":
			// Empty line = event boundary.
			if len(dataLines) == 0 {
				// Heartbeat / keep-alive with no data; skip to next event.
				continue
			}
			// Join multi-line data (rare but valid per spec).
			payload := strings.Join(dataLines, "\n")
			dataLines = dataLines[:0]

			var value T
			if err := json.Unmarshal([]byte(payload), &value); err != nil {
				return zero, fmt.Errorf("sse: decoding event data: %w", err)
			}
			return value, nil
		}
	}

	// Scanner stopped — either EOF or error.
	s.done = true
	if err := s.scanner.Err(); err != nil {
		return zero, fmt.Errorf("sse: reading stream: %w", err)
	}
	return zero, io.EOF
}

// Close closes the underlying response body, releasing the connection.
func (s *EventStream[T]) Close() error {
	s.done = true
	return s.resp.Body.Close()
}
