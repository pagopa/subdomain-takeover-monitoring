package slack

import (
	"errors"
	"testing"
)

func TestFormatBulletList(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  string
	}{
		{name: "empty", items: nil, want: ""},
		{name: "single", items: []string{"a -> b"}, want: "• a -> b"},
		{name: "multiple", items: []string{"a", "b"}, want: "• a\n• b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatBulletList(tt.items); got != tt.want {
				t.Errorf("FormatBulletList() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNotifyScanResult(t *testing.T) {
	const (
		channelID      = "MAIN"
		channelIDDebug = "DEBUG"
	)

	tests := []struct {
		name            string
		realItems       []string
		canaryFound     bool
		wantChannel     string
		wantAttachments bool
	}{
		{
			name:        "canary not found alerts debug channel",
			realItems:   []string{"real -> res"},
			canaryFound: false,
			wantChannel: channelIDDebug,
		},
		{
			name:            "real items alert main channel with attachment",
			realItems:       []string{"real -> res"},
			canaryFound:     true,
			wantChannel:     channelID,
			wantAttachments: true,
		},
		{
			name:        "all secure notifies debug channel",
			realItems:   nil,
			canaryFound: true,
			wantChannel: channelIDDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotChannel string
			var gotAttachments []string

			original := sendNotification
			sendNotification = func(ch string, _ string, attachments ...string) error {
				gotChannel = ch
				gotAttachments = attachments
				return nil
			}
			t.Cleanup(func() { sendNotification = original })

			if err := NotifyScanResult("aws", channelID, channelIDDebug, tt.realItems, tt.canaryFound); err != nil {
				t.Fatalf("NotifyScanResult() unexpected error: %v", err)
			}
			if gotChannel != tt.wantChannel {
				t.Errorf("channel = %q, want %q", gotChannel, tt.wantChannel)
			}
			if tt.wantAttachments && len(gotAttachments) == 0 {
				t.Errorf("expected an attachment with the resource list, got none")
			}
			if !tt.wantAttachments && len(gotAttachments) != 0 {
				t.Errorf("expected no attachments, got %v", gotAttachments)
			}
		})
	}
}

func TestNotifyScanResultPropagatesError(t *testing.T) {
	wantErr := errors.New("delivery failed")
	original := sendNotification
	sendNotification = func(string, string, ...string) error { return wantErr }
	t.Cleanup(func() { sendNotification = original })

	if err := NotifyScanResult("azure", "MAIN", "DEBUG", nil, true); !errors.Is(err, wantErr) {
		t.Errorf("NotifyScanResult() error = %v, want %v", err, wantErr)
	}
}
