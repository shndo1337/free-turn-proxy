package vkauth

import (
	"strings"
	"testing"
)

func TestVKCallsRespToken(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in   map[string]any
		want string
	}{
		"present":      {map[string]any{"response": map[string]any{"token": "abc"}}, "abc"},
		"no response":  {map[string]any{"error": map[string]any{}}, ""},
		"no token":     {map[string]any{"response": map[string]any{"foo": "bar"}}, ""},
		"wrong type":   {map[string]any{"response": map[string]any{"token": 42}}, ""},
		"response nil": {map[string]any{"response": nil}, ""},
	}
	for name, tc := range cases {
		if got := vkCallsRespToken(tc.in); got != tc.want {
			t.Errorf("%s: vkCallsRespToken = %q, want %q", name, got, tc.want)
		}
	}
}

func TestVKCallsErr(t *testing.T) {
	t.Parallel()

	if err := vkCallsErr(map[string]any{"response": map[string]any{"token": "x"}}); err != nil {
		t.Errorf("no error envelope should yield nil, got %v", err)
	}

	err := vkCallsErr(map[string]any{"error": map[string]any{
		"error_code": float64(29),
		"error_msg":  "Rate limit reached",
	}})
	if err == nil {
		t.Fatal("expected error for error envelope")
	}
	// fetch() keys its rate-limit heuristic off the "error_code:29" substring.
	if !strings.Contains(err.Error(), "error_code:29") {
		t.Errorf("error text %q missing error_code:29", err.Error())
	}
}
