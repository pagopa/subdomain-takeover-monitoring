package selftest

import (
	"strings"
	"testing"
)

func TestAzureCanaryMatches(t *testing.T) {
	canary := AzureCanary{
		DNSZoneName:        "ab12cd34ef56.net",
		StorageAccountName: "mystorageab12cd34ef56",
	}

	tests := []struct {
		TestName string
		Item     string
		Want     bool
	}{
		{
			TestName: "matches by fqdn zone",
			Item:     "www.ab12cd34ef56.net -> mystorageab12cd34ef56.blob.core.windows.net",
			Want:     true,
		},
		{
			TestName: "does not match a different zone",
			Item:     "app.example.com -> app.azurewebsites.net",
			Want:     false,
		},
		{
			TestName: "does not match empty item",
			Item:     "",
			Want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			if got := canary.Matches(tt.Item); got != tt.Want {
				t.Errorf("Matches(%q) = %v, want %v", tt.Item, got, tt.Want)
			}
		})
	}
}

func TestAzureCanarySplit(t *testing.T) {
	canary := AzureCanary{DNSZoneName: "ab12cd34ef56.net"}
	canaryItem := "www.ab12cd34ef56.net -> mystorageab12cd34ef56.blob.core.windows.net"
	realItem1 := "app.example.com -> app.azurewebsites.net"
	realItem2 := "cdn.example.org -> example.blob.core.windows.net"

	tests := []struct {
		TestName  string
		Items     []string
		WantReal  []string
		WantFound bool
	}{
		{
			TestName:  "canary alongside real items",
			Items:     []string{realItem1, canaryItem, realItem2},
			WantReal:  []string{realItem1, realItem2},
			WantFound: true,
		},
		{
			TestName:  "canary only",
			Items:     []string{canaryItem},
			WantReal:  nil,
			WantFound: true,
		},
		{
			TestName:  "real items only, canary missing",
			Items:     []string{realItem1, realItem2},
			WantReal:  []string{realItem1, realItem2},
			WantFound: false,
		},
		{
			TestName:  "empty input",
			Items:     nil,
			WantReal:  nil,
			WantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			gotReal, gotFound := canary.Split(tt.Items)
			if gotFound != tt.WantFound {
				t.Errorf("Split found = %v, want %v", gotFound, tt.WantFound)
			}
			if !equalStringSlices(gotReal, tt.WantReal) {
				t.Errorf("Split real = %v, want %v", gotReal, tt.WantReal)
			}
		})
	}
}

func TestGenerateAzureNames(t *testing.T) {
	rgName, dnsZoneName, storageAccountName, err := generateAzureNames()
	if err != nil {
		t.Fatalf("generateAzureNames returned error: %v", err)
	}

	tests := []struct {
		TestName string
		Check    func(t *testing.T)
	}{
		{
			TestName: "resource group uses self-test prefix",
			Check: func(t *testing.T) {
				if !strings.HasPrefix(rgName, azureRGPrefix) {
					t.Errorf("rgName = %q, want prefix %q", rgName, azureRGPrefix)
				}
			},
		},
		{
			TestName: "dns zone ends with .net",
			Check: func(t *testing.T) {
				if !strings.HasSuffix(dnsZoneName, ".net") {
					t.Errorf("dnsZoneName = %q, want suffix .net", dnsZoneName)
				}
			},
		},
		{
			TestName: "storage account is lowercase and within 24 chars",
			Check: func(t *testing.T) {
				if len(storageAccountName) > 24 {
					t.Errorf("storageAccountName %q has len %d, want <= 24", storageAccountName, len(storageAccountName))
				}
				if storageAccountName != strings.ToLower(storageAccountName) {
					t.Errorf("storageAccountName %q is not lowercase", storageAccountName)
				}
			},
		},
		{
			TestName: "resource group recognised as self-test zone",
			Check: func(t *testing.T) {
				if !IsSelfTestZone(rgName) {
					t.Errorf("IsSelfTestZone(%q) = false, want true", rgName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, tt.Check)
	}
}

func TestAzureStorageCNAME(t *testing.T) {
	canary := AzureCanary{StorageAccountName: "mystorageab12cd34ef56"}
	want := "mystorageab12cd34ef56.blob.core.windows.net"
	if got := canary.StorageCNAME(); got != want {
		t.Errorf("StorageCNAME() = %q, want %q", got, want)
	}
}
