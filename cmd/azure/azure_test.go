package main

import (
	"strings"
	"testing"
)

// Test per la funzione getResourceGroupFromID
func TestGetResourceGroupFromID(t *testing.T) {
	tests := []struct {
		resourceID string
		want       string
		wantErr    bool
	}{
		{"", "", true},
		{"/subscriptions/123/resourceGroups/myResourceGroup/resources/456", "myResourceGroup", false},
		{"/subscriptions/123/resourceGroup/myResourceGroup/resources/456", "", true},
		{"/subscriptions/123/resourceGroups/myResourceGroup", "myResourceGroup", false},
	}

	for _, tt := range tests {
		t.Run(tt.resourceID, func(t *testing.T) {
			got, err := getResourceGroupFromID(tt.resourceID)
			if (err != nil) != tt.wantErr {
				t.Errorf("getResourceGroupFromID()= %v, error = %v, wantErr %v", got, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getResourceGroupFromID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test per la funzione Lookup
func TestLookup(t *testing.T) {
	tests := []struct {
		name      string
		resources map[string]struct{}
		cname     string
		expected  bool
	}{
		{
			name:      "existing cname",
			resources: map[string]struct{}{"example.com": {}, "test.com": {}},
			cname:     "example.com",
			expected:  false,
		},
		{
			name:      "non-existing cname",
			resources: map[string]struct{}{"example.com": {}, "test.com": {}},
			cname:     "notfound.com",
			expected:  true,
		},
		{
			name:      "empty resources",
			resources: map[string]struct{}{},
			cname:     "example.com",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Lookup(tt.resources, tt.cname)
			if result != tt.expected {
				t.Errorf("Lookup(%v, %s) = %v; expected %v", tt.resources, tt.cname, result, tt.expected)
			}
		})
	}
}

// Helper function to compare two slices
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

func TestGetQuery(t *testing.T) {

	got := getQuery("./query.txt")
	want := `resources
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
| order by dnsEndpoint asc, name asc, id asc`

	if !strings.EqualFold(got, want) {
		t.Errorf("Res %v", strings.EqualFold(got, want))
	}

}
