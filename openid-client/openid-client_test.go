package main

import (
	"testing"
)

func TestReverse(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
	}

	for _, c := range cases {
		got := Reverse()
		if got != c.want {
			t.Errorf("Reverse(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}

func Reverse() interface{} {
	return ""
}
