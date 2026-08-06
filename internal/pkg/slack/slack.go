package slack

import (
	"fmt"
	"log/slog"
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

// sendNotification is the function used to deliver messages. It is a package
// variable so tests can substitute a fake sender instead of calling Slack.
var sendNotification = SendSlackNotification

// NotifyScanResult sends the appropriate Slack notification for a scan outcome:
//   - the canary was not detected
//   - real dangling records were found
//   - otherwise: everything is secure
func NotifyScanResult(org string, channelID string, channelIDDebug string, realItems []string, canaryFound bool) error {
	switch {
	case !canaryFound:
		slog.Error("Self-test failed: the canary dangling record was not detected")
		message := fmt.Sprintf("Self-test FAILED in %s: the canary dangling record was not detected, so the scanner may be broken.", org)
		return sendNotification(channelIDDebug, message)
	case len(realItems) > 0:
		resourceListText := FormatBulletList(realItems)
		message := fmt.Sprintf("Attention: Potentially vulnerable resources detected in %s. These may be susceptible to subdomain takeover.\nThe pointed resources do not seem to belong to the organization. Please remove any dangling DNS records from the hosted zones to mitigate the risk.\n", org)
		return sendNotification(channelID, message, resourceListText)
	default:
		message := fmt.Sprintf("All DNS records in %s are secure and properly configured.", org)
		return sendNotification(channelIDDebug, message)
	}
}
