package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"subdomain/internal/pkg/logger"
	"subdomain/internal/pkg/slack"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/aws/aws-lambda-go/lambda"
)

const (
	AZURE_ORG = "azure"
)

func getResourceGroupFromResourceID(resourceID string) (string, error) {
	const resourceGroupsKey = "resourceGroups"
	resourceComponents := strings.Split(resourceID, "/")

	for i := range resourceComponents {
		if strings.EqualFold(resourceComponents[i], resourceGroupsKey) {
			if i+1 < len(resourceComponents) {
				return resourceComponents[i+1], nil
			}
			return "", fmt.Errorf("resource group not found in resource ID")
		}
	}
	return "", fmt.Errorf("resource group key not found in resource ID")
}

func containsAzureVulnerableResources(resource string) bool {
	azureVulnerableDomains := []string{
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

	for _, domain := range azureVulnerableDomains {
		if strings.Contains(resource, domain) {
			return true
		}
	}
	return false
}

func getDnsCNAMERecords(resources map[string]struct{}, dnsZone armdns.Zone, subscriptionID string) ([]string, error) {
	var vulnerableResources []string
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a credential: %v", err)
	}
	cntx := context.Background()
	clientFactory, err := armdns.NewClientFactory(subscriptionID, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err)
	}
	resourceGroup, err := getResourceGroupFromResourceID(*dnsZone.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource group: %v", err)
	}

	recordSetPager := clientFactory.NewRecordSetsClient().NewListByTypePager(resourceGroup, *dnsZone.Name, armdns.RecordTypeCNAME, &armdns.RecordSetsClientListByTypeOptions{})
	for recordSetPager.More() {
		page, err := recordSetPager.NextPage(cntx)
		if err != nil {
			return nil, fmt.Errorf("recordSetPager failed to advance page: %v", err)
		}

		for _, record := range page.Value {
			props := record.Properties
			if props == nil || props.CnameRecord == nil || props.CnameRecord.Cname == nil || props.Fqdn == nil {
				continue
			}

			fqdn := *props.Fqdn
			cname := strings.TrimRight(strings.TrimSpace(*props.CnameRecord.Cname), ".")

			if !containsAzureVulnerableResources(cname) {
				continue
			}

			if strings.Contains(cname, "azureedge.net") {
				splits := strings.Split(cname, ".")
				if len(splits) >= 4 {
					cname = strings.Join(splits[len(splits)-3:], ".")
				}
			}

			if isVulnerableResource(resources, cname) {
				vulnerableResources = append(vulnerableResources, fqdn+" -> "+cname)
			}
		}
	}

	return vulnerableResources, nil

}

func isVulnerableResource(resources map[string]struct{}, cname string) bool {
	_, exists := resources[cname]
	return !exists
}

func readQueryFile(filePath string) (string, error) {
	queryData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read the file: %v", err)
	}
	return string(queryData), nil
}

func getAllAzureSubscriptions() ([]string, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a credential: %v", err)
	}
	cntx := context.Background()
	clientFactory, err := armsubscriptions.NewClientFactory(credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err)
	}

	var subscriptionIDs []string
	pager := clientFactory.NewClient().NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(cntx)
		if err != nil {
			return nil, fmt.Errorf("subs pager failed to advance page: %v", err)
		}
		for _, subscription := range page.Value {
			subscriptionIDs = append(subscriptionIDs, *subscription.SubscriptionID)
		}
	}
	return subscriptionIDs, nil
}

func HandleRequest(ctx context.Context, event interface{}) (string, error) {
	slog.Info("Starting handlerequest")
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to obtain a credential: %v", err)
	}
	cntx := context.Background()
	resourceGraphClientFactory, err := armresourcegraph.NewClientFactory(credential, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create resource graph client: %v", err)
	}

	query, err := readQueryFile("./query")
	if err != nil {
		return "", err
	}
	resourceQueryRequest := armresourcegraph.QueryRequest{
		Query: to.Ptr(query),
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}
	allVulnerableResources := make(map[string]struct{})
	for {
		resourceQueryResult, err := resourceGraphClientFactory.NewClient().Resources(cntx, resourceQueryRequest, nil)
		if err != nil {
			return "", fmt.Errorf("resource query failed: %v", err)
		}

		if resourceItems, ok := resourceQueryResult.Data.([]interface{}); ok {
			for _, resourceItem := range resourceItems {
				if resourceMap, ok := resourceItem.(map[string]interface{}); ok {
					if dnsEndpoint, ok := resourceMap["dnsEndpoint"].(string); ok {
						allVulnerableResources[dnsEndpoint] = struct{}{}
					}
				}
			}
		}

		if resourceQueryResult.QueryResponse.SkipToken == nil || *resourceQueryResult.QueryResponse.SkipToken == "" {
			break
		} else {
			resourceQueryRequest.Options.SkipToken = resourceQueryResult.QueryResponse.SkipToken
		}
	}
	slog.Info("resources query completed successfully")

	subscriptionIDs, err := getAllAzureSubscriptions()
	if err != nil {
		return "", err
	}
	slog.Info("getAllAzureSubscriptions completed successfully")
	var detectedVulnerabilities []string
	for _, subscriptionID := range subscriptionIDs {
		clientFactory, err := armdns.NewClientFactory(subscriptionID, credential, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create DNS client: %v", err)
		}

		dnsZonesPager := clientFactory.NewZonesClient().NewListPager(&armdns.ZonesClientListOptions{})
		for dnsZonesPager.More() {
			page, err := dnsZonesPager.NextPage(cntx)
			if err != nil {
				if strings.Contains(err.Error(), "does not exist") {
					break
				}
				return "", fmt.Errorf("dnsZonesPager failed to advance page: %v", err)
			}
			for _, dnsZone := range page.Value {
				cnameRecords, err := getDnsCNAMERecords(allVulnerableResources, *dnsZone, subscriptionID)
				if err != nil {
					return "", err
				}
				detectedVulnerabilities = append(detectedVulnerabilities, cnameRecords...)
			}
		}
	}
	slog.Info("DNS zone analysis completed successfully")
	err = slack.SendSlackNotification(detectedVulnerabilities, AZURE_ORG)

	if err != nil {
		return "", fmt.Errorf("slack notification failed %v", err)
	}
	slog.Info("HandleRequest completed successfully")
	return "HandleRequest completed successfully", nil
}

func main() {
	logger.SetupLogger(slog.LevelDebug)
	slog.Info("Starting Lambda")
	lambda.Start(HandleRequest)
}
