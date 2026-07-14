package o2

import (
	"regexp"
	"strings"

	"github.com/rclone/rclone/fs/config/obscure"
)

var rawValidationKeyRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func revealValidationKey(value string) string {
	if rawValidationKeyRe.MatchString(value) {
		return value
	}
	return revealIfObscured(value)
}

func revealJSessionID(value string) string {
	if strings.Contains(value, ".") {
		return value
	}
	return revealIfObscured(value)
}

func revealIfObscured(value string) string {
	if value == "" {
		return ""
	}
	if revealed, err := obscure.Reveal(value); err == nil {
		return revealed
	}
	return value
}

func normalizeDeviceID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "web-") || strings.HasPrefix(value, "fac-") {
		return value
	}
	return "web-" + value
}
