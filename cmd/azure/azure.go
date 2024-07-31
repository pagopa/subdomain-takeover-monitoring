package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/slack-go/slack"
)

type MyEvent struct {
	Name string `json:"name"`
}

func getResourceGroupFromID(resourceID string) (string, error) {
	const resourceGroupsKey = "resourceGroups"

	components := strings.Split(resourceID, "/")

	for i := range components {
		if strings.EqualFold(components[i], resourceGroupsKey) {
			if i+1 < len(components) {
				return components[i+1], nil
			}
			return "", fmt.Errorf("resource group not found in resource ID")
		}
	}

	return "", fmt.Errorf("resource group key not found in resource ID")
}

func containsAzureVulnerableResources(x string) bool {
	azureDomains := []string{
		"azure-api.net",
		"azurecontainer.io",
		"azurefd.net",
		"azureedge.net",
		"azurewebsites.net",
		"blob.core.windows.net",
		"cloudapp.azure.com",
		"cloudapp.net",
		"trafficmanager.net",
	}

	for _, domain := range azureDomains {
		if strings.Contains(x, domain) {
			return true
		}
	}
	return false
}

func DnsToCNAME(resources map[string]struct{}, DNSZone armdns.Zone, subscriptionID string) []string {
	var alerts []string
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armdns.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	rg, err := getResourceGroupFromID(*DNSZone.ID)
	if err != nil {
		log.Fatalf("failed to get RG: %v", err)
	}
	// get the cname records
	pager := clientFactory.NewRecordSetsClient().NewListByTypePager(rg, *DNSZone.Name, armdns.RecordTypeCNAME, &armdns.RecordSetsClientListByTypeOptions{Top: nil,
		Recordsetnamesuffix: nil,
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range page.Value {
			if v.Properties != nil && v.Properties.CnameRecord != nil && v.Properties.CnameRecord.Cname != nil && v.Properties.Fqdn != nil {
				x := strings.TrimSpace(*v.Properties.CnameRecord.Cname)
				x = strings.TrimRight(x, ".")
				if containsAzureVulnerableResources(x) {
					if strings.Contains(x, "azureedge.net") {
						splits := strings.Split(x, ".")
						if len(splits) >= 4 {
							x = strings.Join(splits[len(splits)-3:], ".")
						}
					}
					if Lookup(resources, x) {
						alerts = append(alerts, strings.Join([]string{*v.Properties.Fqdn, x}, "->"))
					}

				}
			}
		}
	}
	return alerts
}

func Lookup(resources map[string]struct{}, cname string) bool {
	if _, ok := resources[cname]; ok {
		return false
	} else {
		return true
	}

}

func getQuery(nameFile string) string {
	res, err := os.ReadFile(nameFile)
	if err != nil {
		log.Fatalf("failed to read the file: %v", err)
	}
	return string(res)
}

func getAllSubscriptions() []string {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	cntx := context.Background()
	clientFactorySub, err := armsubscriptions.NewClientFactory(cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	var resAllSubscriptions []string
	pager := clientFactorySub.NewClient().NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(cntx)
		if err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range page.Value {
			resAllSubscriptions = append(resAllSubscriptions, *v.SubscriptionID)
		}
	}
	return resAllSubscriptions
}

func notify(res []string) {
	initialText := "🚨🧐 One or more resources potentially susceptible to subdomain takeover have been identified 🧐🚨"
	tokenSlack := os.Getenv("SLACK_TOKEN")
	channelId := os.Getenv("CHANNEL_ID")
	api := slack.New(tokenSlack)

	// Formatting in MD
	var listItems []string
	for _, item := range res {
		listItems = append(listItems, "• "+item)
	}
	listText := strings.Join(listItems, "\n")

	attachments := []slack.Attachment{
		{
			Text: listText,
		},
	}

	_, _, err := api.PostMessage(channelId, slack.MsgOptionText(initialText, true), slack.MsgOptionAttachments(attachments...))
	if err != nil {
		log.Fatalf("slack errror: %v", err)
	}
}

func HandleRequest(ctx context.Context, event MyEvent) (string, error) {
	//
	// Authentication with service principal
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	cntx := context.Background()
	clientFactoryRes, err := armresourcegraph.NewClientFactory(cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	// read the query from the file
	query := getQuery("./query.txt")
	// Query to list all the organization resources that could be vulnerable to subdomain takeover
	request := armresourcegraph.QueryRequest{
		Query: to.Ptr(query),
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}
	var allResources = make(map[string]struct{})
	for {
		resAllResources, err := clientFactoryRes.NewClient().Resources(cntx, request, nil)
		if err != nil {
			log.Fatalf("failed to finish the request: %v", err)
		}

		//Parsing
		if m, ok := resAllResources.Data.([]interface{}); ok {
			for _, r := range m {
				if items, ok := r.(map[string]interface{}); ok {
					if x, ok := items["dnsEndpoint"].(string); ok {
						allResources[x] = struct{}{}
					}
				}
			}
		}
		//Paging
		if resAllResources.QueryResponse.SkipToken == nil || *resAllResources.QueryResponse.SkipToken == "" {
			break
		} else {
			request.Options.SkipToken = resAllResources.QueryResponse.SkipToken
		}
	}
	//get all the subscriptions
	resAllSubscriptions := getAllSubscriptions()
	var result []string
	//for each subscription
	for _, x := range resAllSubscriptions {
		clientFactory, err := armdns.NewClientFactory(x, cred, nil)
		if err != nil {
			log.Fatalf("failed to create client: %v", err)
		}

		//get all the dnszone
		pager := clientFactory.NewZonesClient().NewListPager(&armdns.ZonesClientListOptions{Top: nil})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				log.Fatalf("failed to advance page: %v", err)
			}
			for _, v := range page.Value {

				result = append(result, DnsToCNAME(allResources, *v, x)...)
			}
		}
	}

	// report of the subdomains
	if len(result) > 0 {
		notify(result)
		resultStamp := strings.Join(result, "|")
		return resultStamp, nil
	} else {
		return "No subdomain", nil
	}

}

func main() {
	lambda.Start(HandleRequest)
}
