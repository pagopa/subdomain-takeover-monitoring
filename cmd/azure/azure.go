package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/aws/aws-lambda-go/lambda"
)

const (
	AZURE_ORG                    = "azure"
	UNHAPPY_CHECK_RG_PREFIX      = "demo-rg-subdomain"
	UNHAPPY_CHECK_LOCATION       = "italynorth"
	UNHAPPY_CHECK_RECORD         = "www"
	UNHAPPY_CHECK_STORAGE_PREFIX = "mystorage"
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

func getDnsCNAMERecords(ctx context.Context, resources map[string]struct{}, dnsZone armdns.Zone, clientFactory *armdns.ClientFactory) ([]string, error) {
	var vulnerableResources []string
	resourceGroup, err := getResourceGroupFromResourceID(*dnsZone.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource group: %v", err)
	}

	recordSetPager := clientFactory.NewRecordSetsClient().NewListByTypePager(resourceGroup, *dnsZone.Name, armdns.RecordTypeCNAME, &armdns.RecordSetsClientListByTypeOptions{})
	for recordSetPager.More() {
		page, err := recordSetPager.NextPage(ctx)
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

func formatBulletList(items []string) string {
	var formatted []string
	for _, item := range items {
		formatted = append(formatted, "• "+item)
	}
	return strings.Join(formatted, "\n")
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

// buildExistingAzureResources runs the Resource Graph query and AFD custom domain
// enrichment to produce the set of known-existing Azure endpoints. A CNAME whose
// target is absent from this map is considered dangling (vulnerable).
func buildExistingAzureResources(ctx context.Context, credential *azidentity.DefaultAzureCredential) (map[string]struct{}, []string, error) {
	resourceGraphClientFactory, err := armresourcegraph.NewClientFactory(credential, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create resource graph client: %v", err)
	}

	query, err := readQueryFile("./query")
	if err != nil {
		return nil, nil, err
	}
	resourceQueryRequest := armresourcegraph.QueryRequest{
		Query: to.Ptr(query),
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}
	existingResources := make(map[string]struct{})
	for {
		resourceQueryResult, err := resourceGraphClientFactory.NewClient().Resources(ctx, resourceQueryRequest, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("resource query failed: %v", err)
		}
		if resourceItems, ok := resourceQueryResult.Data.([]interface{}); ok {
			for _, resourceItem := range resourceItems {
				if resourceMap, ok := resourceItem.(map[string]interface{}); ok {
					if dnsEndpoint, ok := resourceMap["dnsEndpoint"].(string); ok {
						existingResources[dnsEndpoint] = struct{}{}
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
		return nil, nil, err
	}
	slog.Info("getAllAzureSubscriptions completed successfully")

	// Retrieve custom domains from AFD resources. This is required to handle the edge case
	// where a classic CDN is migrated to Azure Front Door using the Microsoft migration tool.
	// In such cases, the old CDN endpoint becomes a custom domain of the new Front Door,
	// and a new AFD endpoint is created.
	// This leads to a false positive in subdomain checks, as the CNAME still points to the old endpoint.
	// Unfortunately, custom domains are not available in the Azure Resource Graph, so the
	// information must be retrieved via the ARM API.

	if err := getCustomDomains(existingResources, subscriptionIDs); err != nil {
		return nil, nil, fmt.Errorf("failed to get custom domains: %w", err)
	}

	return existingResources, subscriptionIDs, nil
}

func HandleRequest(ctx context.Context, event interface{}) (string, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to obtain a credential: %v", err)
	}

	if err := runUnhappyPathCheck(credential); err != nil {
		slog.Error("Unhappy path check failed", "Error", err.Error())
		if notifyErr := slack.SendSlackNotification(os.Getenv("CHANNEL_ID_DEBUG"), fmt.Sprintf("Self-test ERROR in %s: %s", AZURE_ORG, err.Error())); notifyErr != nil {
			slog.Error("Failed to send Slack message", "Error", notifyErr.Error())
		}
	}

	existingResources, subscriptionIDs, err := buildExistingAzureResources(ctx, credential)
	if err != nil {
		return "", err
	}

	var detectedVulnerabilities []string
	for _, subscriptionID := range subscriptionIDs {
		clientFactory, err := armdns.NewClientFactory(subscriptionID, credential, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create DNS client: %v", err)
		}

		dnsZonesPager := clientFactory.NewZonesClient().NewListPager(&armdns.ZonesClientListOptions{})
		for dnsZonesPager.More() {
			page, err := dnsZonesPager.NextPage(ctx)
			if err != nil {
				if strings.Contains(err.Error(), "does not exist") {
					break
				}
				return "", fmt.Errorf("dnsZonesPager failed to advance page: %v", err)
			}
			for _, dnsZone := range page.Value {
				// Skip DNS zones that belong to self-test resource groups.
				// Teardown is async so these may still be visible.
				if isAzureSelfTestZone(*dnsZone) {
					continue
				}
				cnameRecords, err := getDnsCNAMERecords(ctx, existingResources, *dnsZone, clientFactory)
				if err != nil {
					return "", err
				}
				detectedVulnerabilities = append(detectedVulnerabilities, cnameRecords...)
			}
		}
	}
	slog.Info("Subdomain takeover monitoring tool has correctly verified all Azure accounts belonging to organization.")

	slackChannelID := os.Getenv("CHANNEL_ID")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
	if len(detectedVulnerabilities) > 0 {
		resourceListText := formatBulletList(detectedVulnerabilities)
		message := fmt.Sprintf("Attention: Potentially vulnerable resources detected in %s. These may be susceptible to subdomain takeover.\nThe pointed resources do not seem to belong to the organization. Please remove any dangling DNS records from the hosted zones to mitigate the risk.\n", AZURE_ORG)
		err = slack.SendSlackNotification(slackChannelID, message, resourceListText)
	} else {
		message := fmt.Sprintf("All DNS records in %s are secure and properly configured.", AZURE_ORG)
		err = slack.SendSlackNotification(slackChannelIDDebug, message)
	}
	if err != nil {
		return "", fmt.Errorf("slack notification failed %v", err)
	}
	slog.Debug("Subdomain takeover monitoring tool sent the result of execution via Slack.")
	return "HandleRequest completed successfully", nil
}

// getCustomDomains retrieves all custom domains from Azure Front Door (AFD) profiles
// across multiple Azure subscriptions and adds them to the existing resources map.
// Parameters:
//   - existingResources: map to store discovered custom domain names
//   - subscriptionIDs: slice of Azure subscription IDs to scan
//
// Returns error if authentication, client creation, or API calls fail
func getCustomDomains(existingResources map[string]struct{}, subscriptionIDs []string) error {
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
		// Add each custom domain to the existing resources map
		// Using empty struct{} as value for memory efficiency (set-like behavior)
		for _, v := range customdomains {
			existingResources[v] = struct{}{}
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

func generateAzureTestNames() (rgName string, dnsZoneName string, storageAccountName string, err error) {
	b := make([]byte, 6)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	hexStr := hex.EncodeToString(b)
	rgName = fmt.Sprintf("%s-%s", UNHAPPY_CHECK_RG_PREFIX, hexStr)
	dnsZoneName = fmt.Sprintf("%s.net", hexStr)
	raw := strings.ToLower(UNHAPPY_CHECK_STORAGE_PREFIX + hexStr)
	if len(raw) > 24 {
		raw = raw[:24]
	}
	storageAccountName = raw
	return rgName, dnsZoneName, storageAccountName, nil
}

func azureSelfTestCNAME(storageAccountName string) string {
	return fmt.Sprintf("%s.blob.core.windows.net", storageAccountName)
}

func isAzureSelfTestZone(dnsZone armdns.Zone) bool {
	if dnsZone.ID == nil {
		return false
	}
	rg, err := getResourceGroupFromResourceID(*dnsZone.ID)
	if err != nil {
		return false
	}
	return strings.HasPrefix(rg, UNHAPPY_CHECK_RG_PREFIX)
}

func setupAzureDanglingCNAME(ctx context.Context, credential *azidentity.DefaultAzureCredential, subscriptionID string, rgName string, dnsZoneName string, storageAccountName string) (armdns.Zone, error) {
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, credential, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: NewResourceGroupsClient failed: %w", err)
	}
	_, err = rgClient.CreateOrUpdate(ctx, rgName, armresources.ResourceGroup{
		Location: to.Ptr(UNHAPPY_CHECK_LOCATION),
	}, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: CreateOrUpdate resource group failed: %w", err)
	}

	storageClient, err := armstorage.NewAccountsClient(subscriptionID, credential, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: NewAccountsClient failed: %w", err)
	}
	poller, err := storageClient.BeginCreate(ctx, rgName, storageAccountName, armstorage.AccountCreateParameters{
		SKU:      &armstorage.SKU{Name: to.Ptr(armstorage.SKUNameStandardLRS)},
		Kind:     to.Ptr(armstorage.KindStorageV2),
		Location: to.Ptr(UNHAPPY_CHECK_LOCATION),
		Properties: &armstorage.AccountPropertiesCreateParameters{
			AccessTier: to.Ptr(armstorage.AccessTierHot),
		},
	}, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: BeginCreate storage account failed: %w", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: PollUntilDone storage account failed: %w", err)
	}

	dnsClientFactory, err := armdns.NewClientFactory(subscriptionID, credential, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: NewClientFactory DNS failed: %w", err)
	}
	zoneResp, err := dnsClientFactory.NewZonesClient().CreateOrUpdate(ctx, rgName, dnsZoneName, armdns.Zone{
		Location: to.Ptr("global"),
	}, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: CreateOrUpdate DNS zone failed: %w", err)
	}

	cname := azureSelfTestCNAME(storageAccountName)
	_, err = dnsClientFactory.NewRecordSetsClient().CreateOrUpdate(ctx, rgName, dnsZoneName, UNHAPPY_CHECK_RECORD, armdns.RecordTypeCNAME, armdns.RecordSet{
		Properties: &armdns.RecordSetProperties{
			TTL:         to.Ptr(int64(300)),
			CnameRecord: &armdns.CnameRecord{Cname: to.Ptr(cname)},
		},
	}, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: CreateOrUpdate CNAME record failed: %w", err)
	}

	_, err = storageClient.Delete(ctx, rgName, storageAccountName, nil)
	if err != nil {
		return armdns.Zone{}, fmt.Errorf("setupAzureDanglingCNAME: Delete storage account failed: %w", err)
	}

	return zoneResp.Zone, nil
}

func teardownAzureDanglingCNAME(credential *azidentity.DefaultAzureCredential, subscriptionID string, rgName string) {
	// Use a fresh background context so cleanup is not cancelled if the handler context expires.
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, credential, nil)
	if err != nil {
		slog.Error("teardownAzureDanglingCNAME: NewResourceGroupsClient failed", "Error", err.Error())
		return
	}
	_, err = rgClient.BeginDelete(context.Background(), rgName, nil)
	if err != nil {
		slog.Error("teardownAzureDanglingCNAME: BeginDelete resource group failed", "Error", err.Error())
	}
}

func runUnhappyPathCheck(credential *azidentity.DefaultAzureCredential) error {
	// Use a background context for the entire self-test so setup/scan are not
	// cancelled if the Lambda handler context is close to its deadline. Setup
	// can take 30-90s; cancellation mid-poll would leave half-created resources.
	selfTestCtx := context.Background()

	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		return fmt.Errorf("runUnhappyPathCheck: AZURE_SUBSCRIPTION_ID env var not set")
	}

	rgName, dnsZoneName, storageAccountName, err := generateAzureTestNames()
	if err != nil {
		return err
	}

	zone, err := setupAzureDanglingCNAME(selfTestCtx, credential, subscriptionID, rgName, dnsZoneName, storageAccountName)
	defer teardownAzureDanglingCNAME(credential, subscriptionID, rgName)
	if err != nil {
		return err
	}

	// Take the resource snapshot AFTER setup (which creates and then deletes the
	// storage account). This way the snapshot faithfully reflects the dangling
	// state: the CNAME target is genuinely missing from the Resource Graph.
	// Taking the snapshot before setup would make the test PASS trivially because
	// the just-created storage account was never in the snapshot to begin with.
	existingResources, _, err := buildExistingAzureResources(selfTestCtx, credential)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: buildExistingAzureResources failed: %w", err)
	}

	// Resource Graph is eventually consistent: the just-deleted test storage
	// account may still appear in existingResources for several minutes. We KNOW
	// it was deleted, so explicitly drop it from the snapshot to ensure the test
	// reports the dangling state correctly regardless of Graph propagation lag.
	testCNAME := azureSelfTestCNAME(storageAccountName)
	delete(existingResources, testCNAME)

	dnsClientFactory, err := armdns.NewClientFactory(subscriptionID, credential, nil)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: NewClientFactory failed: %w", err)
	}

	cnameRecords, err := getDnsCNAMERecords(selfTestCtx, existingResources, zone, dnsClientFactory)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: getDnsCNAMERecords failed: %w", err)
	}

	if len(cnameRecords) == 0 {
		slog.Error("Unhappy path check: failed to detect expected dangling record", "dnsZone", dnsZoneName, "rgName", rgName)
		return slack.SendSlackNotification(os.Getenv("CHANNEL_ID_DEBUG"), fmt.Sprintf("Self-test FAILED: dangling record in %s for test zone %s was NOT detected.", AZURE_ORG, dnsZoneName))
	}

	return nil
}
