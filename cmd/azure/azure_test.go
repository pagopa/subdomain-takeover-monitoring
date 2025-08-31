package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockAFDProfilesPager struct {
	mock.Mock
}

func (m *mockAFDProfilesPager) More() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockAFDProfilesPager) NextPage(ctx context.Context) (armcdn.ProfilesClientListResponse, error) {
	args := m.Called(ctx)
	return args.Get(0).(armcdn.ProfilesClientListResponse), args.Error(1)
}

type mockAFDProfilesClient struct {
	mock.Mock
}

func (m *mockAFDProfilesClient) NewListPager(opt *armcdn.ProfilesClientListOptions) AFDProfilesPager {
	args := m.Called(opt)
	return args.Get(0).(AFDProfilesPager)
}

type mockAFDCustomDomainsPager struct {
	mock.Mock
}

func (m *mockAFDCustomDomainsPager) More() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockAFDCustomDomainsPager) NextPage(ctx context.Context) (armcdn.AFDCustomDomainsClientListByProfileResponse, error) {
	args := m.Called(ctx)
	return args.Get(0).(armcdn.AFDCustomDomainsClientListByProfileResponse), args.Error(1)
}

type mockAFDCustomDomainsClient struct {
	mock.Mock
}

func (m *mockAFDCustomDomainsClient) NewListByProfilePager(resourceGroupName string, profileName string, options *armcdn.AFDCustomDomainsClientListByProfileOptions) AFDCustomDomainsPager {
	args := m.Called(resourceGroupName, profileName, options)
	return args.Get(0).(AFDCustomDomainsPager)
}

type mockClientFactory struct {
	mock.Mock
}

func (m *mockClientFactory) NewAFDCustomDomainsClient() AFDCustomDomainsClient {
	args := m.Called()
	return args.Get(0).(AFDCustomDomainsClient)
}

func (m *mockClientFactory) NewAFDProfilesClient() AFDProfilesClient {
	args := m.Called()
	return args.Get(0).(AFDProfilesClient)
}

// Test getResourceGroupFromID
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
			}
			if got != tt.want {
				t.Errorf("getResourceGroupFromID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test Lookup
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
func TestReadQueryFile(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		expectedErr bool
	}{
		{
			name: "Valid file",
			setupFile: func(t *testing.T) string {
				// Create a temporary file
				tmpfile := t.TempDir() + "/query.txt"
				content := "resources | where type == 'Microsoft.Cdn/profiles'"
				err := writeTestFile(tmpfile, content)
				require.NoError(t, err)
				return tmpfile
			},
			expectedErr: false,
		},
		{
			name: "Non-existent file",
			setupFile: func(t *testing.T) string {
				return "/non/existent/file.txt"
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile(t)

			result, err := readQueryFile(filePath)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Empty(t, result)
				assert.Contains(t, err.Error(), "failed to read the file")
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

// Helper function to write test files
func writeTestFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// Benchmark tests
func BenchmarkContainsAzureVulnerableResources(b *testing.B) {
	testResource := "myapp.azurefd.net"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containsAzureVulnerableResources(testResource)
	}
}

func BenchmarkIsVulnerableResource(b *testing.B) {
	resources := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		resources[fmt.Sprintf("resource%d.azurefd.net", i)] = struct{}{}
	}
	testCname := "test.azurefd.net"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isVulnerableResource(resources, testCname)
	}
}

// Table-driven test for AFDProfile struct
func TestAFDProfile(t *testing.T) {
	tests := []struct {
		name         string
		profile      AFDProfile
		expectedName string
		expectedRG   string
	}{
		{
			name: "Valid AFDProfile",
			profile: AFDProfile{
				Name:          "test-profile",
				ResourceGroup: "test-rg",
			},
			expectedName: "test-profile",
			expectedRG:   "test-rg",
		},
		{
			name: "Empty AFDProfile",
			profile: AFDProfile{
				Name:          "",
				ResourceGroup: "",
			},
			expectedName: "",
			expectedRG:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedName, tt.profile.Name)
			assert.Equal(t, tt.expectedRG, tt.profile.ResourceGroup)
		})
	}
}

// Test for edge cases in domain processing
func TestDomainProcessingEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "azureedge.net with subdomain",
			input:    "cdn-endpoint.azureedge.net",
			expected: "cdn-endpoint.azureedge.net",
		},
		{
			name:     "azureedge.net with multiple subdomains",
			input:    "sub.cdn-endpoint.azureedge.net",
			expected: "cdn-endpoint.azureedge.net", // Should extract last 3 parts
		},
		{
			name:     "Regular domain",
			input:    "example.com",
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the logic that would be in getDnsCNAMERecords
			// for processing azureedge.net domains
			cname := strings.TrimRight(strings.TrimSpace(tt.input), ".")

			if strings.Contains(cname, "azureedge.net") {
				splits := strings.Split(cname, ".")
				if len(splits) >= 4 {
					cname = strings.Join(splits[len(splits)-3:], ".")
				}
			}

			assert.Equal(t, tt.expected, cname)
		})
	}
}

// Test constants
func TestConstants(t *testing.T) {
	assert.Equal(t, "azure", AZURE_ORG)
}

// Test for error handling patterns
func TestErrorHandlingPatterns(t *testing.T) {
	tests := []struct {
		name        string
		errorFunc   func() error
		expectedMsg string
	}{
		{
			name: "Resource group parsing error",
			errorFunc: func() error {
				_, err := getResourceGroupFromResourceID("invalid-id")
				return err
			},
			expectedMsg: "resource group key not found",
		},
		{
			name: "File reading error",
			errorFunc: func() error {
				_, err := readQueryFile("/non/existent/file")
				return err
			},
			expectedMsg: "failed to read the file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errorFunc()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedMsg)
		})
	}
}

// Test for getAFDProfile function
func TestGetAFDProfile(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func() *mockClientFactory
		expectedResult []AFDProfile
		expectedError  string
	}{
		{
			name: "successful retrieval of profiles",
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockProfilesClient := &mockAFDProfilesClient{}
				mockPager := &mockAFDProfilesPager{}

				// Setup mock responses
				profiles := []*armcdn.Profile{
					{
						ID:   to.Ptr("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Cdn/profiles/profile1"),
						Name: to.Ptr("profile1"),
					},
					{
						ID:   to.Ptr("/subscriptions/sub1/resourceGroups/rg2/providers/Microsoft.Cdn/profiles/profile2"),
						Name: to.Ptr("profile2"),
					},
				}

				response := armcdn.ProfilesClientListResponse{
					ProfileListResult: armcdn.ProfileListResult{
						Value: profiles,
					},
				}

				// First call to More() returns true, second returns false
				mockPager.On("More").Return(true).Once()
				mockPager.On("More").Return(false).Once()
				mockPager.On("NextPage", mock.Anything).Return(response, nil).Once()

				mockProfilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDProfilesClient").Return(mockProfilesClient)

				return mockFactory
			},
			expectedResult: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
				{Name: "profile2", ResourceGroup: "rg2"},
			},
			expectedError: "",
		},
		{
			name: "no profiles found",
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockProfilesClient := &mockAFDProfilesClient{}
				mockPager := &mockAFDProfilesPager{}

				response := armcdn.ProfilesClientListResponse{
					ProfileListResult: armcdn.ProfileListResult{
						Value: []*armcdn.Profile{},
					},
				}

				mockPager.On("More").Return(true).Once()
				mockPager.On("More").Return(false).Once()
				mockPager.On("NextPage", mock.Anything).Return(response, nil).Once()

				mockProfilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDProfilesClient").Return(mockProfilesClient)

				return mockFactory
			},
			expectedResult: nil,
			expectedError:  "",
		},
		{
			name: "error during pagination",
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockProfilesClient := &mockAFDProfilesClient{}
				mockPager := &mockAFDProfilesPager{}

				mockPager.On("More").Return(true).Once()
				mockPager.On("NextPage", mock.Anything).Return(armcdn.ProfilesClientListResponse{}, errors.New("pagination error"))

				mockProfilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDProfilesClient").Return(mockProfilesClient)

				return mockFactory
			},
			expectedResult: nil,
			expectedError:  "failed to advance page in getAFDProfile: pagination error",
		},
		{
			name: "invalid resource ID",
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockProfilesClient := &mockAFDProfilesClient{}
				mockPager := &mockAFDProfilesPager{}

				profiles := []*armcdn.Profile{
					{
						ID:   to.Ptr("invalid-resource-id"),
						Name: to.Ptr("profile1"),
					},
				}

				response := armcdn.ProfilesClientListResponse{
					ProfileListResult: armcdn.ProfileListResult{
						Value: profiles,
					},
				}

				mockPager.On("More").Return(true).Once()
				mockPager.On("More").Return(false).Once()
				mockPager.On("NextPage", mock.Anything).Return(response, nil).Once()

				mockProfilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDProfilesClient").Return(mockProfilesClient)

				return mockFactory
			},
			expectedResult: nil,
			expectedError:  "resource group key not found in resource ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFactory := tt.setupMocks()
			ctx := context.Background()

			result, err := getAFDProfile(mockFactory, ctx)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			// Verify all expectations were met
			mockFactory.AssertExpectations(t)
		})
	}
}

// Test for getAFDCustomDomains function
func TestGetAFDCustomDomains(t *testing.T) {
	tests := []struct {
		name           string
		profiles       []AFDProfile
		setupMocks     func() *mockClientFactory
		expectedResult []string
		expectedError  string
	}{
		{
			name: "successful retrieval of custom domains",
			profiles: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
				{Name: "profile2", ResourceGroup: "rg2"},
			},
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockCustomDomainsClient := &mockAFDCustomDomainsClient{}
				mockPager1 := &mockAFDCustomDomainsPager{}
				mockPager2 := &mockAFDCustomDomainsPager{}

				// Setup custom domains for profile1
				domains1 := []*armcdn.AFDDomain{
					{
						Properties: &armcdn.AFDDomainProperties{
							HostName: to.Ptr("example1.com"),
						},
					},
					{
						Properties: &armcdn.AFDDomainProperties{
							HostName: to.Ptr("example2.com"),
						},
					},
				}

				response1 := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: domains1,
					},
				}

				// Setup custom domains for profile2
				domains2 := []*armcdn.AFDDomain{
					{
						Properties: &armcdn.AFDDomainProperties{
							HostName: to.Ptr("example3.com"),
						},
					},
				}

				response2 := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: domains2,
					},
				}

				// Setup pager for profile1
				mockPager1.On("More").Return(true).Once()
				mockPager1.On("More").Return(false).Once()
				mockPager1.On("NextPage", mock.Anything).Return(response1, nil).Once()

				// Setup pager for profile2
				mockPager2.On("More").Return(true).Once()
				mockPager2.On("More").Return(false).Once()
				mockPager2.On("NextPage", mock.Anything).Return(response2, nil).Once()

				mockCustomDomainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(mockPager1)
				mockCustomDomainsClient.On("NewListByProfilePager", "rg2", "profile2", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(mockPager2)
				mockFactory.On("NewAFDCustomDomainsClient").Return(mockCustomDomainsClient)

				return mockFactory
			},
			expectedResult: []string{"example1.com", "example2.com", "example3.com"},
			expectedError:  "",
		},
		{
			name:     "no profiles provided",
			profiles: []AFDProfile{},
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				return mockFactory
			},
			expectedResult: nil,
			expectedError:  "",
		},
		{
			name: "profile with no custom domains",
			profiles: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
			},
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockCustomDomainsClient := &mockAFDCustomDomainsClient{}
				mockPager := &mockAFDCustomDomainsPager{}

				response := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: []*armcdn.AFDDomain{},
					},
				}

				mockPager.On("More").Return(true).Once()
				mockPager.On("More").Return(false).Once()
				mockPager.On("NextPage", mock.Anything).Return(response, nil).Once()

				mockCustomDomainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDCustomDomainsClient").Return(mockCustomDomainsClient)

				return mockFactory
			},
			expectedResult: nil,
			expectedError:  "",
		},
		{
			name: "domains with nil properties",
			profiles: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
			},
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockCustomDomainsClient := &mockAFDCustomDomainsClient{}
				mockPager := &mockAFDCustomDomainsPager{}

				domains := []*armcdn.AFDDomain{
					{
						Properties: nil, // This should be skipped
					},
					{
						Properties: &armcdn.AFDDomainProperties{
							HostName: nil, // This should be skipped
						},
					},
					{
						Properties: &armcdn.AFDDomainProperties{
							HostName: to.Ptr("valid.com"), // This should be included
						},
					},
				}

				response := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: domains,
					},
				}

				mockPager.On("More").Return(true).Once()
				mockPager.On("More").Return(false).Once()
				mockPager.On("NextPage", mock.Anything).Return(response, nil).Once()

				mockCustomDomainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDCustomDomainsClient").Return(mockCustomDomainsClient)

				return mockFactory
			},
			expectedResult: []string{"valid.com"},
			expectedError:  "",
		},
		{
			name: "pagination error",
			profiles: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
			},
			setupMocks: func() *mockClientFactory {
				mockFactory := &mockClientFactory{}
				mockCustomDomainsClient := &mockAFDCustomDomainsClient{}
				mockPager := &mockAFDCustomDomainsPager{}

				mockPager.On("More").Return(true).Once()
				mockPager.On("NextPage", mock.Anything).Return(armcdn.AFDCustomDomainsClientListByProfileResponse{}, errors.New("pagination failed"))

				mockCustomDomainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(mockPager)
				mockFactory.On("NewAFDCustomDomainsClient").Return(mockCustomDomainsClient)

				return mockFactory
			},
			expectedResult: nil,
			expectedError:  "failed to advance page in getAFDCustomDomains : pagination failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFactory := tt.setupMocks()
			ctx := context.Background()

			result, err := getAFDCustomDomains(mockFactory, tt.profiles, ctx)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			// Verify all expectations were met
			mockFactory.AssertExpectations(t)
		})
	}
}
