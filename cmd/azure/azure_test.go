package main

import (
	_ "embed"
	"strings"
	"testing"
)

// Test per la funzione getResourceGroupFromID
func TestGetResourceGroupFromResourceID(t *testing.T) {
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
			got, err := getResourceGroupFromResourceID(tt.resourceID)
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
func TestIsVulnerableResource(t *testing.T) {
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
			result := isVulnerableResource(tt.resources, tt.cname)
			if result != tt.expected {
				t.Errorf("Lookup(%v, %s) = %v; expected %v", tt.resources, tt.cname, result, tt.expected)
			}
		})
	}
}

// Test containsAzureVulnerableResources
func TestContainsAzureVulnerableResources(t *testing.T) {
	tests := []struct {
		resource string
		expected bool
	}{
		{"example.azurewebsites.net", true},
		{"example.com", false},
		{"test.trafficmanager.net", true},
	}

	for _, test := range tests {
		result := containsAzureVulnerableResources(test.resource)
		if result != test.expected {
			t.Fatalf("expected %v, got %v for resource %s", test.expected, result, test.resource)
		}
	}
}

//go:embed query
var want string

func TestReadQueryFile(t *testing.T) {
	got, err := readQueryFile("./query")
	if err != nil {
		t.Fatalf("Error reading query file: %v", err)
	}

	if !strings.EqualFold(got, want) {
		t.Errorf("Mismatch in query file content.\nGot: %v\nWant: %v", got, want)
	}
}
