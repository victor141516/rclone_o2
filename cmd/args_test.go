package cmd

import (
	"reflect"
	"testing"
)

func TestRedactedArgs(t *testing.T) {
	args := []string{
		"rclone", "config", "update", "o2",
		"--state", "session-state",
		"--result=123456",
		"config_sms_code", "654321",
		"config_sms_code=112233",
		"--non-interactive",
	}
	want := []string{
		"rclone", "config", "update", "o2",
		"--state", "REDACTED",
		"--result=REDACTED",
		"config_sms_code", "REDACTED",
		"config_sms_code=REDACTED",
		"--non-interactive",
	}
	got := redactedArgs(args)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redacted args = %#v, want %#v", got, want)
	}
	if args[5] != "session-state" || args[6] != "--result=123456" || args[8] != "654321" || args[9] != "config_sms_code=112233" {
		t.Fatalf("redactedArgs modified its input: %#v", args)
	}
}
