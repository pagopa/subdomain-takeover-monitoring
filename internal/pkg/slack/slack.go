package slack

import (
	"os"

	slackapi "github.com/slack-go/slack"
)

func SendSlackNotification(channelID string, message string, attachmentTexts ...string) error {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackClient := slackapi.New(slackToken)

	var attachments []slackapi.Attachment
	for _, text := range attachmentTexts {
		attachments = append(attachments, slackapi.Attachment{Text: text})
	}

	_, _, err := slackClient.PostMessage(channelID, slackapi.MsgOptionText(message, true), slackapi.MsgOptionAttachments(attachments...))
	return err
}
