package selftest

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

const (
	azureRGPrefix      = "demo-rg-subdomain"
	azureLocation      = "italynorth"
	azureRecordName    = "www"
	azureStoragePrefix = "mystorage"
)

// AzureCanary holds the disposable Azure resources created for one self-test run.
type AzureCanary struct {
	SubscriptionID     string
	RGName             string
	DNSZoneName        string // e.g. "ab12cd34ef56.net"
	StorageAccountName string
}

// StorageCNAME returns the blob endpoint the canary CNAME points to. The storage
// account is deleted during setup, so this endpoint is the dangling target.
func (c AzureCanary) StorageCNAME() string {
	return fmt.Sprintf("%s.blob.core.windows.net", c.StorageAccountName)
}

// Matches reports whether a scan result item refers to this canary. Scan items
// are formatted as "fqdn -> cname"; the fqdn contains the canary's unique DNS zone.
func (c AzureCanary) Matches(item string) bool {
	return strings.Contains(item, c.DNSZoneName)
}

// Split separates the real dangling records from the canary among the scan
// results. found reports whether the scan detected the canary, which proves the
// scanner is still working.
func (c AzureCanary) Split(items []string) (real []string, found bool) {
	for _, item := range items {
		if c.Matches(item) {
			found = true
			continue
		}
		real = append(real, item)
	}
	return real, found
}

// IsSelfTestZone reports whether a resource group belongs to a self-test run,
// so real scans can recognise (and skip) leftover canary zones.
func IsSelfTestZone(rgName string) bool {
	return strings.HasPrefix(rgName, azureRGPrefix)
}

// generateAzureNames returns a random resource group, DNS zone and storage
// account name for one self-test run. Storage account names are capped at 24
// lowercase alphanumeric characters as required by Azure.
func generateAzureNames() (rgName string, dnsZoneName string, storageAccountName string, err error) {
	hexStr, err := randomHex(6)
	if err != nil {
		return "", "", "", err
	}
	rgName = fmt.Sprintf("%s-%s", azureRGPrefix, hexStr)
	dnsZoneName = hexStr + ".net"
	storageAccountName = strings.ToLower(azureStoragePrefix + hexStr)
	if len(storageAccountName) > 24 {
		storageAccountName = storageAccountName[:24]
	}
	return rgName, dnsZoneName, storageAccountName, nil
}

// SetupAzureDanglingCNAME creates a resource group, a storage account, a DNS zone
// and a CNAME pointing to the storage account, then deletes the storage account
// so the record becomes dangling. The returned AzureCanary is always safe to pass
// to Teardown, even when an error is returned.
func SetupAzureDanglingCNAME(ctx context.Context, credential *azidentity.DefaultAzureCredential, subscriptionID string) (AzureCanary, error) {
	rgName, dnsZoneName, storageAccountName, err := generateAzureNames()
	if err != nil {
		return AzureCanary{}, err
	}
	canary := AzureCanary{
		SubscriptionID:     subscriptionID,
		RGName:             rgName,
		DNSZoneName:        dnsZoneName,
		StorageAccountName: storageAccountName,
	}

	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, credential, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: new resource groups client failed: %w", err)
	}
	_, err = rgClient.CreateOrUpdate(ctx, rgName, armresources.ResourceGroup{
		Location: to.Ptr(azureLocation),
	}, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: create resource group failed: %w", err)
	}

	storageClient, err := armstorage.NewAccountsClient(subscriptionID, credential, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: new accounts client failed: %w", err)
	}
	poller, err := storageClient.BeginCreate(ctx, rgName, storageAccountName, armstorage.AccountCreateParameters{
		SKU:      &armstorage.SKU{Name: to.Ptr(armstorage.SKUNameStandardLRS)},
		Kind:     to.Ptr(armstorage.KindStorageV2),
		Location: to.Ptr(azureLocation),
		Properties: &armstorage.AccountPropertiesCreateParameters{
			AccessTier: to.Ptr(armstorage.AccessTierHot),
		},
	}, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: begin create storage account failed: %w", err)
	}
	if _, err = poller.PollUntilDone(ctx, nil); err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: poll storage account failed: %w", err)
	}

	dnsClientFactory, err := armdns.NewClientFactory(subscriptionID, credential, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: new DNS client factory failed: %w", err)
	}
	_, err = dnsClientFactory.NewZonesClient().CreateOrUpdate(ctx, rgName, dnsZoneName, armdns.Zone{
		Location: to.Ptr("global"),
	}, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: create DNS zone failed: %w", err)
	}

	_, err = dnsClientFactory.NewRecordSetsClient().CreateOrUpdate(ctx, rgName, dnsZoneName, azureRecordName, armdns.RecordTypeCNAME, armdns.RecordSet{
		Properties: &armdns.RecordSetProperties{
			TTL:         to.Ptr(int64(300)),
			CnameRecord: &armdns.CnameRecord{Cname: to.Ptr(canary.StorageCNAME())},
		},
	}, nil)
	if err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: create CNAME record failed: %w", err)
	}

	// Delete the storage account so the CNAME is left dangling.
	if _, err = storageClient.Delete(ctx, rgName, storageAccountName, nil); err != nil {
		return canary, fmt.Errorf("setupAzureDanglingCNAME: delete storage account failed: %w", err)
	}

	return canary, nil
}

// Teardown removes every resource created for the canary by deleting its resource
// group. It uses a background context so cleanup is not cancelled if the handler
// context is close to its deadline.
func (c AzureCanary) Teardown(credential *azidentity.DefaultAzureCredential) error {
	rgClient, err := armresources.NewResourceGroupsClient(c.SubscriptionID, credential, nil)
	if err != nil {
		return fmt.Errorf("teardown: new resource groups client failed: %w", err)
	}
	if _, err = rgClient.BeginDelete(context.Background(), c.RGName, nil); err != nil {
		return fmt.Errorf("teardown: begin delete resource group failed: %w", err)
	}
	return nil
}
