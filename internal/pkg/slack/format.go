package slack

import "strings"

// FormatBulletList renders a slice of items as a newline-separated bullet list.
func FormatBulletList(items []string) string {
	var formatted []string
	for _, item := range items {
		formatted = append(formatted, "• "+item)
	}
	return strings.Join(formatted, "\n")
}
