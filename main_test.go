package main

import (
	"reflect"
	"testing"
)

func TestNormalizeFlagArgsAllowsFlagsAfterPositional(t *testing.T) {
	got := normalizeFlagArgs(
		[]string{"input/example.yaml", "-target", "loon", "-o", "/tmp/out.conf"},
		map[string]bool{"-target": true, "-input": true, "-o": true},
	)
	want := []string{"-target", "loon", "-o", "/tmp/out.conf", "input/example.yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeFlagArgs() = %#v, want %#v", got, want)
	}
}

func TestNormalizeFlagArgsAllowsEqualsForm(t *testing.T) {
	got := normalizeFlagArgs(
		[]string{"input/example.yaml", "-target=egern"},
		map[string]bool{"-target": true},
	)
	want := []string{"-target=egern", "input/example.yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeFlagArgs() = %#v, want %#v", got, want)
	}
}

func TestNormalizeFlagArgsKeepsLoonSource(t *testing.T) {
	got := normalizeFlagArgs([]string{"input/loon.conf", "-source", "loon", "-target", "qx"}, map[string]bool{"-source": true, "-target": true})
	want := []string{"-source", "loon", "-target", "qx", "input/loon.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeFlagArgs() = %#v, want %#v", got, want)
	}
}
