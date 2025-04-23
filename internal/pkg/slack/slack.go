package slack

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/slack-go/slack"
)

const (
	badNotificationText  = "Attention: Potentially vulnerable resources detected in %s. These may be susceptible to subdomain takeover. The affected resources do not belong to PagoPA’s tenants. Please remove any dangling DNS records from the hosted zones to mitigate the risk."
	goodNotificationText = "All DNS records in %s are secure and properly configured."
)

func SendSlackNotification(vulnerableResources []string, cloud_provider string) error {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackChannelID := os.Getenv("CHANNEL_ID")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
	slackClient := slack.New(slackToken)

	slog.Info(fmt.Sprintf("Cloud provider: %s", cloud_provider))
	slog.Info(fmt.Sprintf("Number of vulnerable resources: %d", len(vulnerableResources)))

	if len(vulnerableResources) > 0 {
		slog.Info("Vulnerable resources detected")
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
		slog.Info(fmt.Sprintf("Vulnerable resources: %s", resourceListText))
		_, _, err := slackClient.PostMessage(slackChannelID, slack.MsgOptionText(fmt.Sprintf(badNotificationText, cloud_provider), true), slack.MsgOptionAttachments(attachments...))
		if err != nil {
			return err
		}
		slog.Info("Alert message sent successfully")
	} else {
		_, _, err := slackClient.PostMessage(slackChannelIDDebug, slack.MsgOptionText(fmt.Sprintf(goodNotificationText, cloud_provider), true), slack.MsgOptionAttachments())
		if err != nil {
			return err
		}
		slog.Info("Alert message sent successfully")
	}
	return nil
}
