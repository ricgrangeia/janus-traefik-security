package llm

import "testing"

func TestExtractJSONObject(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", `{"a":1}`, `{"a":1}`},
		{"with prose prefix", `Here is the result:\n{"a":1}`, `{"a":1}`},
		{"markdown fence", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{"trailing prose", `{"a":1}\nThat's the answer.`, `{"a":1}`},
		{"nested objects", `{"a":{"b":2},"c":[1,2,3]}`, `{"a":{"b":2},"c":[1,2,3]}`},
		{"brace inside string", `{"a":"with } brace"}`, `{"a":"with } brace"}`},
		{"escaped quote inside string", `{"a":"he said \"hi\""}`, `{"a":"he said \"hi\""}`},
		{"no object", `just text`, ``},
		{"unbalanced", `{"a":1`, ``},
		{"second object ignored", `{"a":1} extra {"b":2}`, `{"a":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractJSONObject(tc.in)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
