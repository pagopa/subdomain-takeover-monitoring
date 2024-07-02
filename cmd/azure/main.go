package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/aws/aws-lambda-go/lambda"
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

func DnsToCNAME(allCNAMEs map[string]*armdns.RecordSet, DNSZone armdns.Zone, subscriptionID string) {
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
			x := strings.Trim(*v.Properties.Fqdn, " ")
			x = strings.TrimRight(x, ".")
			allCNAMEs[x] = v
		}
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

	// Query to list alla the organization resources that could be vulnerable to subdomain takeover
	resAllResources, err := clientFactoryRes.NewClient().Resources(cntx, armresourcegraph.QueryRequest{
		Query: to.Ptr(`
    resources
    | where type in ('microsoft.network/frontdoors',
    'microsoft.storage/storageaccounts',
    'microsoft.cdn/profiles/endpoints',
    'microsoft.cdn/profiles/afdendpoints',
    'microsoft.network/publicipaddresses',
    'microsoft.network/trafficmanagerprofiles',
    'microsoft.containerinstance/containergroups',
    'microsoft.apimanagement/service',
    'microsoft.web/sites',
    'microsoft.web/sites/slots',
    'microsoft.classiccompute/domainnames',    
    'microsoft.classicstorage/storageaccounts')
    |mvexpand properties.hostnameConfigurations    
    | extend dnsEndpoint = case
    (
       type =~ 'microsoft.network/frontdoors', properties.cName,
       type =~ 'microsoft.storage/storageaccounts', iff(properties['primaryEndpoints']['blob'] matches regex '(?i)(http|https)://',
                parse_url(tostring(properties['primaryEndpoints']['blob'])).Host, tostring(properties['primaryEndpoints']['blob'])),
       type =~ 'microsoft.cdn/profiles/endpoints', properties.hostName,
       type =~ 'microsoft.cdn/profiles/afdendpoints', properties.hostName,
       type =~ 'microsoft.network/publicipaddresses', properties.dnsSettings.fqdn,
       type =~ 'microsoft.network/trafficmanagerprofiles', properties.dnsConfig.fqdn,
       type =~ 'microsoft.containerinstance/containergroups', properties.ipAddress.fqdn,
       type =~ 'microsoft.apimanagement/service', properties_hostnameConfigurations.hostName,
       type =~ 'microsoft.web/sites', properties.defaultHostName,
       type =~ 'microsoft.web/sites/slots', properties.defaultHostName,
       type =~ 'microsoft.classiccompute/domainnames',properties.hostName,
       ''
    )
    | extend dnsEndpoints = case
    (
        type =~ 'microsoft.apimanagement/service', 
           pack_array(dnsEndpoint, 
            parse_url(tostring(properties.gatewayRegionalUrl)).Host,
            parse_url(tostring(properties.developerPortalUrl)).Host, 
            parse_url(tostring(properties.managementApiUrl)).Host,
            parse_url(tostring(properties.portalUrl)).Host,
            parse_url(tostring(properties.scmUrl)).Host,
            parse_url(tostring(properties.gatewayUrl)).Host),
        type =~ 'microsoft.web/sites', properties.hostNames,
       	type =~ 'microsoft.web/sites/slots', properties.hostNames,
        type =~ 'microsoft.classicstorage/storageaccounts', properties.endpoints,
        pack_array(dnsEndpoint)
    )
    | where isnotempty(dnsEndpoint)
    | extend resourceProvider = case
    (
        dnsEndpoint endswith 'azure-api.net', 'azure-api.net',
        dnsEndpoint endswith 'azurecontainer.io', 'azurecontainer.io',
        dnsEndpoint endswith 'azureedge.net', 'azureedge.net',
        dnsEndpoint endswith 'azurefd.net', 'azurefd.net',
        dnsEndpoint endswith 'azurewebsites.net', 'azurewebsites.net',
        dnsEndpoint endswith 'blob.core.windows.net', 'blob.core.windows.net', 
        dnsEndpoint endswith 'cloudapp.azure.com', 'cloudapp.azure.com',
        dnsEndpoint endswith 'cloudapp.net', 'cloudapp.net',
        dnsEndpoint endswith 'trafficmanager.net', 'trafficmanager.net',
        '' 
    )
    | project id, tenantId, subscriptionId, type, resourceGroup, name, dnsEndpoint, dnsEndpoints, properties, resourceProvider
    | order by dnsEndpoint asc, name asc, id asc`),
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}

	//get all the subscriptions
	clientFactorySub, err := armsubscriptions.NewClientFactory(cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	var allCNAMEs = make(map[string]*armdns.RecordSet)
	var resAllSubscriptions []string
	pager := clientFactorySub.NewClient().NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range page.Value {
			resAllSubscriptions = append(resAllSubscriptions, *v.ID)
		}
	}

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

				DnsToCNAME(allCNAMEs, *v, x)
			}
		}
	}

	// lookup if cname exist in the org

	return fmt.Sprintf("Hello, %s!", event.Name), nil
}

func main() {
	lambda.Start(HandleRequest)
}
