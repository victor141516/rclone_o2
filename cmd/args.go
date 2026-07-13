package cmd

import "strings"

var sensitiveConfigArgs = []string{"--state", "--result", "config_sms_code"}

func redactedArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	for i := range redacted {
		for _, argName := range sensitiveConfigArgs {
			switch {
			case redacted[i] == argName && i+1 < len(redacted):
				redacted[i+1] = "REDACTED"
			case strings.HasPrefix(redacted[i], argName+"="):
				redacted[i] = argName + "=REDACTED"
			}
		}
	}
	return redacted
}
