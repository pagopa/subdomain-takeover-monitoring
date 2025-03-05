package slack

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/slack-go/slack"
)

const (
	badNotificationText  = "Attention: Potentially vulnerable resources detected in %s, susceptible to subdomain takeover."
	goodNotificationText = "Everything is under control on the %s org!"
)

func SendSlackNotification(vulnerableResources []string, cloud_provider string) error {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackChannelID := os.Getenv("CHANNEL_ID")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
	slackClient := slack.New(slackToken)

	log.Printf("Cloud provider: %s", cloud_provider)
	log.Printf("Number of vulnerable resources: %d", len(vulnerableResources))

	if len(vulnerableResources) > 0 {
		log.Println("Vulnerable resources detected")
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
		log.Printf("Vulnerable resources: %s", resourceListText)
		_, _, err := slackClient.PostMessage(slackChannelID, slack.MsgOptionText(fmt.Sprintf(badNotificationText, cloud_provider), true), slack.MsgOptionAttachments(attachments...))
		if err != nil {
			return err
		}
		log.Println("Alert message sent successfully")
	} else {
		_, _, err := slackClient.PostMessage(slackChannelIDDebug, slack.MsgOptionText(fmt.Sprintf(goodNotificationText, cloud_provider), true), slack.MsgOptionAttachments())
		if err != nil {
			return err
		}
		log.Println("Alert message sent successfully")
	}
	return nil
}
