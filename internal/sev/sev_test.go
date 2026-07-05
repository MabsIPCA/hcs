package sev

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "High": "high", "medium": "medium",
		"LOW": "low", "INFO": "info", "TRACE": "info", "": "", "bogus": "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRankAndAtLeast(t *testing.T) {
	if Rank("critical") <= Rank("high") {
		t.Fatal("critical must outrank high")
	}
	if Rank("bogus") != 0 {
		t.Fatal("unknown severity ranks 0")
	}
	if !AtLeast("critical", "high") {
		t.Error("critical >= high")
	}
	if AtLeast("low", "high") {
		t.Error("low is not >= high")
	}
	if !AtLeast("high", "high") {
		t.Error("high >= high (inclusive)")
	}
}
