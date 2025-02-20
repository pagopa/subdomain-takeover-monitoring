package slack

import (
	"fmt"
	"os"
	"strings"

	"github.com/slack-go/slack"
)

const (
	badNotificationText  = "⚠️🔍 Attention: Potentially vulnerable resources detected in %s, susceptible to subdomain takeover. Take immediate action to secure your infrastructure!"
	goodNotificationText = "🎉🚀 Everything is under control on the %s org!"
)

func SendSlackNotification(vulnerableResources []string, cloud_provider string) error {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackChannelID := os.Getenv("CHANNEL_ID")
	slackClient := slack.New(slackToken)

	if len(vulnerableResources) > 0 {
		var formattedResources []string
		for _, resource := range vulnerableResources {
			formattedResources = append(formattedResources, "• "+resource)
		}
		resourceListText := strings.Join(formattedResources, "\n")

		attachments := []slack.Attachment{
			{
				Text: resourceListText,
			},
		}

		_, _, err := slackClient.PostMessage(slackChannelID, slack.MsgOptionText(fmt.Sprintf(badNotificationText, cloud_provider), true), slack.MsgOptionAttachments(attachments...))
		if err != nil {
			return err
		}
	} else {
		_, _, err := slackClient.PostMessage(slackChannelID, slack.MsgOptionText(fmt.Sprintf(goodNotificationText, cloud_provider), true), slack.MsgOptionAttachments())
		if err != nil {
			return err
		}
	}
	return nil
}
