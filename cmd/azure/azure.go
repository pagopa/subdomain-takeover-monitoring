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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/aws/aws-lambda-go/lambda"
)

const (
	AZURE_ORG = "azure"
)

type AFDProfile struct {
	Name          string
	ResourceGroup string
}

// AFDProfile interface

type AFDProfilesClient interface {
	NewListPager(*armcdn.ProfilesClientListOptions) AFDProfilesPager
}

type AFDProfilesPager interface {
	More() bool
	NextPage(ctx context.Context) (armcdn.ProfilesClientListResponse, error)
}

type wrapperAFDProfilesClient struct {
	client *armcdn.ProfilesClient
}

func (r *wrapperAFDProfilesClient) NewListPager(opt *armcdn.ProfilesClientListOptions) AFDProfilesPager {
	return r.client.NewListPager(opt)
}

// AFDCustomDomains interface

type AFDCustomDomainsClient interface {
	NewListByProfilePager(resourceGroupName string, profileName string, options *armcdn.AFDCustomDomainsClientListByProfileOptions) AFDCustomDomainsPager
}

type AFDCustomDomainsPager interface {
	More() bool
	NextPage(ctx context.Context) (armcdn.AFDCustomDomainsClientListByProfileResponse, error)
}

type wrapperAFDCustomDomainsClient struct {
	client *armcdn.AFDCustomDomainsClient
}

func (w *wrapperAFDCustomDomainsClient) NewListByProfilePager(resourceGroupName string, profileName string, options *armcdn.AFDCustomDomainsClientListByProfileOptions) AFDCustomDomainsPager {
	return w.client.NewListByProfilePager(resourceGroupName, profileName, options)
}

// ClientFactory interface
type ClientFactory interface {
	NewAFDCustomDomainsClient() AFDCustomDomainsClient
	NewAFDProfilesClient() AFDProfilesClient
}

type wrapperClientFactory struct {
	client *armcdn.ClientFactory
}

func (w *wrapperClientFactory) NewAFDCustomDomainsClient() AFDCustomDomainsClient {
	return &wrapperAFDCustomDomainsClient{client: w.client.NewAFDCustomDomainsClient()}
}

func (w *wrapperClientFactory) NewAFDProfilesClient() AFDProfilesClient {
	return &wrapperAFDProfilesClient{client: w.client.NewProfilesClient()}
}

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
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to obtain a credential: %v", err)
	}
	cntx := context.Background()
	resourceGraphClientFactory, err := armresourcegraph.NewClientFactory(credential, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create resource graph client: %v", err)
	}
	slog.Debug("Resource graph client correctly created")

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
	slog.Debug("Resources query completed successfully")

	subscriptionIDs, err := getAllAzureSubscriptions()
	if err != nil {
		return "", err
	}
	slog.Info("getAllAzureSubscriptions completed successfully")

	// Retrieve custom domains from AFD resources. This is required to handle the edge case
	// where a classic CDN is migrated to Azure Front Door using the Microsoft migration tool.
	// In such cases, the old CDN endpoint becomes a custom domain of the new Front Door,
	// and a new AFD endpoint is created.
	// This leads to a false positive in subdomain checks, as the CNAME still points to the old endpoint.
	// Unfortunately, custom domains are not available in the Azure Resource Graph, so the
	// information must be retrieved via the ARM API.

	getCustomDomains(allVulnerableResources, subscriptionIDs)

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
	slog.Info("Subdomain takeover monitoring tool has correctly verified all Azure accounts belonging to PagoPA organization.")
	err = slack.SendSlackNotification(detectedVulnerabilities, AZURE_ORG)

	if err != nil {
		return "", fmt.Errorf("slack notification failed %v", err)
	}
	slog.Debug("Subdomain takeover monitoring tool sent the result of execution via Slack.")
	return "HandleRequest completed successfully", nil
}

// getCustomDomains retrieves all custom domains from Azure Front Door (AFD) profiles
// across multiple Azure subscriptions and adds them to the vulnerable resources map.
// Parameters:
//   - allVulnerableResources: map to store discovered custom domain names
//   - subscriptionIDs: slice of Azure subscription IDs to scan
//
// Returns error if authentication, client creation, or API calls fail
func getCustomDomains(allVulnerableResources map[string]struct{}, subscriptionIDs []string) error {
	// Initialize Azure authentication using default credential chain
	// (environment variables, managed identity, Azure CLI, etc.)
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	// Iterate through each provided subscription
	for _, sub := range subscriptionIDs {
		clientFactory, err := armcdn.NewClientFactory(sub, credential, nil)
		if err != nil {
			return fmt.Errorf("failed to create clientFactory: %v", err)
		}
		// Get all AFD profiles in the current subscription
		client := &wrapperClientFactory{client: clientFactory}
		profiles, err := getAFDProfile(client, ctx)
		if err != nil {
			return fmt.Errorf("failed to get profile: %v", err)
		}

		slog.Debug("Number of AFD profiles found for subscription", "subscription", sub, "number", len(profiles))
		// Get custom domains from all profiles
		customdomains, err := getAFDCustomDomains(client, profiles, ctx)
		if err != nil {
			return fmt.Errorf("failed to get custom domains: %v", err)
		}
		// Add each custom domain to the vulnerable resources map
		// Using empty struct{} as value for memory efficiency (set-like behavior)
		for _, v := range customdomains {
			allVulnerableResources[v] = struct{}{}
		}
	}
	return nil
}

// getAFDCustomDomains retrieves custom domain names from all provided AFD profiles.
// Uses pagination to handle large numbers of custom domains.
// Parameters:
//   - clientFactory: Azure CDN client factory for API calls
//   - profiles: slice of AFD profiles to query for custom domains
//   - ctx: context for request cancellation and timeouts
//
// Returns slice of custom domain hostnames and any error encountered
func getAFDCustomDomains(clientFactory ClientFactory, profiles []AFDProfile, ctx context.Context) ([]string, error) {
	var domains []string

	for _, p := range profiles {
		pager := clientFactory.NewAFDCustomDomainsClient().NewListByProfilePager(p.ResourceGroup, p.Name, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to advance page in getAFDCustomDomains : %v", err)
			}
			// Extract hostname from each custom domain resource
			for _, v := range page.Value {
				// Check if properties and hostname are not nil before dereferencing
				if v.Properties != nil && v.Properties.HostName != nil {
					slog.Debug("Customdomains found:", "Resource name", p.Name, "domain", v.Properties.HostName)
					domains = append(domains, *v.Properties.HostName)
				}
			}
		}
	}
	return domains, nil
}

// getAFDProfile retrieves all Azure Front Door profiles from the current subscription.
// Uses pagination to handle large numbers of profiles.
// Parameters:
//   - clientFactory: Azure CDN client factory for API calls
//   - ctx: context for request cancellation and timeouts
//
// Returns slice of AFDProfile structs containing profile name and resource group
func getAFDProfile(client ClientFactory, ctx context.Context) ([]AFDProfile, error) {
	pager := client.NewAFDProfilesClient().NewListPager(nil)
	var profiles []AFDProfile
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to advance page in getAFDProfile: %v", err)
		}
		for _, v := range page.Value {
			rg, err := getResourceGroupFromResourceID(*v.ID)
			if err != nil {
				return nil, err
			}
			profiles = append(profiles, AFDProfile{
				Name:          *v.Name,
				ResourceGroup: rg,
			})
		}
	}
	return profiles, nil
}

func main() {
	logger.SetLogger()
	slog.Debug("Starting Lambda")
	lambda.Start(HandleRequest)
}
