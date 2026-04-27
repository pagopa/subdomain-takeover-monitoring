package slack

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/slack-go/slack"
)

const (
	badNotificationText   = "Attention: Potentially vulnerable resources detected in %s. These may be susceptible to subdomain takeover.\nThe pointed resources do not seem to belong to the organization. Please remove any dangling DNS records from the hosted zones to mitigate the risk.\n"
	goodNotificationText  = "All DNS records in %s are secure and properly configured."
	unhappyCheckPassText  = "Self-test PASSED: dangling record in %s correctly detected for test zone %s."
	unhappyCheckFailText  = "Self-test FAILED: dangling record in %s for test zone %s was NOT detected."
	unhappyCheckErrorText = "Self-test ERROR in %s: %s"
)

func SendUnhappyCheckNotification(vulnerableResources []string, cloudProvider string, testZone string) error {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
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
		_, _, err := slackClient.PostMessage(slackChannelIDDebug, slack.MsgOptionText(fmt.Sprintf(unhappyCheckPassText, cloudProvider, testZone), true), slack.MsgOptionAttachments(attachments...))
		if err != nil {
			return err
		}
	} else {
		_, _, err := slackClient.PostMessage(slackChannelIDDebug, slack.MsgOptionText(fmt.Sprintf(unhappyCheckFailText, cloudProvider, testZone), true), slack.MsgOptionAttachments())
		if err != nil {
			return err
		}
	}
	return nil
}

func SendUnhappyCheckError(cloudProvider string, errMsg string) {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
	slackClient := slack.New(slackToken)

	_, _, err := slackClient.PostMessage(slackChannelIDDebug, slack.MsgOptionText(fmt.Sprintf(unhappyCheckErrorText, cloudProvider, errMsg), true))
	if err != nil {
		slog.Error("SendUnhappyCheckError: failed to send Slack message", "Error", err.Error())
	}
}

func SendSlackNotification(vulnerableResources []string, cloud_provider string) error {
	slackToken := os.Getenv("SLACK_TOKEN")
	slackChannelID := os.Getenv("CHANNEL_ID")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
	slackClient := slack.New(slackToken)

	slog.Debug(fmt.Sprintf("Cloud provider: %s", cloud_provider))
	slog.Debug(fmt.Sprintf("Number of vulnerable resources: %d", len(vulnerableResources)))

	if len(vulnerableResources) > 0 {
		slog.Debug("Vulnerable resources detected")
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
		slog.Debug(fmt.Sprintf("Vulnerable resources: %s", resourceListText))
		_, _, err := slackClient.PostMessage(slackChannelID, slack.MsgOptionText(fmt.Sprintf(badNotificationText, cloud_provider), true), slack.MsgOptionAttachments(attachments...))
		if err != nil {
			return err
		}
		slog.Debug("Alert message sent successfully")
	} else {
		_, _, err := slackClient.PostMessage(slackChannelIDDebug, slack.MsgOptionText(fmt.Sprintf(goodNotificationText, cloud_provider), true), slack.MsgOptionAttachments())
		if err != nil {
			return err
		}
		slog.Debug("Alert message sent successfully")
	}
	return nil
}
