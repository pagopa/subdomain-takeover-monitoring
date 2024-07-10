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
			x := strings.TrimSpace(*v.Properties.Fqdn)
			x = strings.TrimRight(x, ".")
			allCNAMEs[x] = v
		}
	}
}

func Lookup(resources map[string]struct{}, allCNAMEs map[string]*armdns.RecordSet) []string {
	var alerts []string
	for i, v := range allCNAMEs {
		if _, ok := resources[i]; ok {

		} else {
			alerts = append(alerts, *v.ID)
		}
	}
	return alerts
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
	var allCNAMEs = make(map[string]*armdns.RecordSet)
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
	result := Lookup(allResources, allCNAMEs)
	// report of the subdomain
	if len(result) > 0 {
		resultStamp := strings.Join(result, "\n")
		return resultStamp, nil
	} else {
		return "No subdomain", nil
	}

}

func main() {
	lambda.Start(HandleRequest)
}
