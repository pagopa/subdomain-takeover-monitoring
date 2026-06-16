package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations

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

func TestGetResourceGroupFromResourceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		resourceID string
		want       string
		wantErr    bool
	}{
		{name: "empty string", resourceID: "", want: "", wantErr: true},
		{name: "valid resource ID", resourceID: "/subscriptions/123/resourceGroups/myResourceGroup/resources/456", want: "myResourceGroup", wantErr: false},
		{name: "missing resourceGroups segment", resourceID: "/subscriptions/123/resourceGroup/myResourceGroup/resources/456", want: "", wantErr: true},
		{name: "resourceGroups at end", resourceID: "/subscriptions/123/resourceGroups/myResourceGroup", want: "myResourceGroup", wantErr: false},
		{name: "resourceGroups with no value", resourceID: "/subscriptions/123/resourceGroups", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := getResourceGroupFromResourceID(tt.resourceID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsVulnerableResource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resources map[string]struct{}
		cname     string
		want      bool
	}{
		{
			name:      "existing cname - not vulnerable",
			resources: map[string]struct{}{"example.com": {}, "test.com": {}},
			cname:     "example.com",
			want:      false,
		},
		{
			name:      "non-existing cname - vulnerable",
			resources: map[string]struct{}{"example.com": {}, "test.com": {}},
			cname:     "notfound.com",
			want:      true,
		},
		{
			name:      "empty resources - vulnerable",
			resources: map[string]struct{}{},
			cname:     "example.com",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isVulnerableResource(tt.resources, tt.cname)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainsAzureVulnerableResources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource string
		want     bool
	}{
		{name: "azurewebsites.net is vulnerable", resource: "example.azurewebsites.net", want: true},
		{name: "plain domain is not vulnerable", resource: "example.com", want: false},
		{name: "trafficmanager.net is vulnerable", resource: "test.trafficmanager.net", want: true},
		{name: "blob.core.windows.net is vulnerable", resource: "account.blob.core.windows.net", want: true},
		{name: "cloudapp.azure.com is vulnerable", resource: "app.cloudapp.azure.com", want: true},
		{name: "azure-api.net is vulnerable", resource: "api.azure-api.net", want: true},
		{name: "azurecontainer.io is vulnerable", resource: "container.azurecontainer.io", want: true},
		{name: "cloudapp.net is vulnerable", resource: "app.cloudapp.net", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := containsAzureVulnerableResources(tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadQueryFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
	}{
		{
			name: "valid file",
			setup: func(t *testing.T) string {
				t.Helper()
				path := t.TempDir() + "/query.txt"
				require.NoError(t, os.WriteFile(path, []byte("resources | where type == 'Microsoft.Cdn/profiles'"), 0644))
				return path
			},
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				t.Helper()
				return "/non/existent/file.txt"
			},
			wantErr: "failed to read the file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := tt.setup(t)
			result, err := readQueryFile(path)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Empty(t, result)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestAFDProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  AFDProfile
		wantRG string
	}{
		{name: "valid profile", input: AFDProfile{Name: "test-profile", ResourceGroup: "test-rg"}, wantRG: "test-rg"},
		{name: "empty profile", input: AFDProfile{}, wantRG: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.name == "valid profile", tt.input.Name == "test-profile")
			assert.Equal(t, tt.wantRG, tt.input.ResourceGroup)
		})
	}
}

func TestGenerateAzureTestNames(t *testing.T) {
	t.Parallel()

	rgName, dnsZoneName, storageAccountName, err := generateAzureTestNames()
	if err != nil {
		log.Fatalln(err)
	}

	if !strings.HasPrefix(rgName, UNHAPPY_CHECK_RG_PREFIX+"-") {
		t.Errorf("rgName should have prefix %s-, got %s", UNHAPPY_CHECK_RG_PREFIX, rgName)
	}
	if !strings.HasSuffix(dnsZoneName, ".net") {
		t.Errorf("dnsZoneName should end with .net, got %s", dnsZoneName)
	}
	if len(dnsZoneName) != 16 {
		t.Errorf("dnsZoneName length should be 16, got %d (%s)", len(dnsZoneName), dnsZoneName)
	}
	if !strings.HasPrefix(storageAccountName, UNHAPPY_CHECK_STORAGE_PREFIX) {
		t.Errorf("storageAccountName should have prefix %s, got %s", UNHAPPY_CHECK_STORAGE_PREFIX, storageAccountName)
	}
	if len(storageAccountName) > 24 {
		t.Errorf("storageAccountName length should be <= 24, got %d (%s)", len(storageAccountName), storageAccountName)
	}
}

func TestGenerateAzureTestNamesUniqueness(t *testing.T) {
	t.Parallel()

	_, dns1, storage1, err := generateAzureTestNames()
	if err != nil {
		log.Fatalln(err)
	}
	_, dns2, storage2, err := generateAzureTestNames()
	if err != nil {
		log.Fatalln(err)
	}
	assert.NotEqual(t, dns1, dns2)
	assert.NotEqual(t, storage1, storage2)
}

func TestAzureSelfTestCNAME(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		storageAccount string
		want           string
	}{
		{name: "standard name", storageAccount: "mystorage123", want: "mystorage123.blob.core.windows.net"},
		{name: "short name", storageAccount: "st", want: "st.blob.core.windows.net"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, azureSelfTestCNAME(tt.storageAccount))
		})
	}
}

func TestIsAzureSelfTestZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		zone armdns.Zone
		want bool
	}{
		{
			name: "self test zone",
			zone: armdns.Zone{ID: to.Ptr("/subscriptions/sub/resourceGroups/demo-rg-subdomain-123/providers/Microsoft.Network/dnsZones/test.net")},
			want: true,
		},
		{
			name: "regular zone",
			zone: armdns.Zone{ID: to.Ptr("/subscriptions/sub/resourceGroups/prod-rg/providers/Microsoft.Network/dnsZones/example.com")},
			want: false,
		},
		{
			name: "invalid resource id",
			zone: armdns.Zone{ID: to.Ptr("invalid")},
			want: false,
		},
		{
			name: "nil id",
			zone: armdns.Zone{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, isAzureSelfTestZone(tt.zone))
		})
	}
}

func TestRunUnhappyPathCheckRequiresSubscriptionID(t *testing.T) {
	originalValue, hadValue := os.LookupEnv("AZURE_SUBSCRIPTION_ID")
	t.Cleanup(func() {
		if hadValue {
			_ = os.Setenv("AZURE_SUBSCRIPTION_ID", originalValue)
			return
		}
		_ = os.Unsetenv("AZURE_SUBSCRIPTION_ID")
	})

	_ = os.Unsetenv("AZURE_SUBSCRIPTION_ID")
	err := runUnhappyPathCheck(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_SUBSCRIPTION_ID env var not set")
}

func TestErrorHandlingPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fn      func() error
		wantMsg string
	}{
		{
			name: "resource group parsing error",
			fn: func() error {
				_, err := getResourceGroupFromResourceID("invalid-id")
				return err
			},
			wantMsg: "resource group key not found",
		},
		{
			name: "file reading error",
			fn: func() error {
				_, err := readQueryFile("/non/existent/file")
				return err
			},
			wantMsg: "failed to read the file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.fn()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

func TestGetAFDProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setupMocks func() *mockClientFactory
		want       []AFDProfile
		wantErr    string
	}{
		{
			name: "successful retrieval of profiles",
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				profilesClient := &mockAFDProfilesClient{}
				pager := &mockAFDProfilesPager{}

				profiles := []*armcdn.Profile{
					{ID: to.Ptr("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Cdn/profiles/profile1"), Name: to.Ptr("profile1")},
					{ID: to.Ptr("/subscriptions/sub1/resourceGroups/rg2/providers/Microsoft.Cdn/profiles/profile2"), Name: to.Ptr("profile2")},
				}
				resp := armcdn.ProfilesClientListResponse{ProfileListResult: armcdn.ProfileListResult{Value: profiles}}

				pager.On("More").Return(true).Once()
				pager.On("More").Return(false).Once()
				pager.On("NextPage", mock.Anything).Return(resp, nil).Once()
				profilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(pager)
				factory.On("NewAFDProfilesClient").Return(profilesClient)
				return factory
			},
			want: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
				{Name: "profile2", ResourceGroup: "rg2"},
			},
		},
		{
			name: "no profiles found",
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				profilesClient := &mockAFDProfilesClient{}
				pager := &mockAFDProfilesPager{}

				resp := armcdn.ProfilesClientListResponse{ProfileListResult: armcdn.ProfileListResult{Value: []*armcdn.Profile{}}}

				pager.On("More").Return(true).Once()
				pager.On("More").Return(false).Once()
				pager.On("NextPage", mock.Anything).Return(resp, nil).Once()
				profilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(pager)
				factory.On("NewAFDProfilesClient").Return(profilesClient)
				return factory
			},
			want: nil,
		},
		{
			name: "pagination error",
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				profilesClient := &mockAFDProfilesClient{}
				pager := &mockAFDProfilesPager{}

				pager.On("More").Return(true).Once()
				pager.On("NextPage", mock.Anything).Return(armcdn.ProfilesClientListResponse{}, errors.New("pagination error"))
				profilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(pager)
				factory.On("NewAFDProfilesClient").Return(profilesClient)
				return factory
			},
			want:    nil,
			wantErr: "failed to advance page in getAFDProfile: pagination error",
		},
		{
			name: "invalid resource ID",
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				profilesClient := &mockAFDProfilesClient{}
				pager := &mockAFDProfilesPager{}

				profiles := []*armcdn.Profile{
					{ID: to.Ptr("invalid-resource-id"), Name: to.Ptr("profile1")},
				}
				resp := armcdn.ProfilesClientListResponse{ProfileListResult: armcdn.ProfileListResult{Value: profiles}}

				pager.On("More").Return(true).Once()
				pager.On("More").Return(false).Once()
				pager.On("NextPage", mock.Anything).Return(resp, nil).Once()
				profilesClient.On("NewListPager", (*armcdn.ProfilesClientListOptions)(nil)).Return(pager)
				factory.On("NewAFDProfilesClient").Return(profilesClient)
				return factory
			},
			want:    nil,
			wantErr: "resource group key not found in resource ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			factory := tt.setupMocks()
			ctx := context.Background()

			result, err := getAFDProfile(factory, ctx)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
			factory.AssertExpectations(t)
		})
	}
}

func TestGetAFDCustomDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		profiles   []AFDProfile
		setupMocks func() *mockClientFactory
		want       []string
		wantErr    string
	}{
		{
			name: "successful retrieval of custom domains",
			profiles: []AFDProfile{
				{Name: "profile1", ResourceGroup: "rg1"},
				{Name: "profile2", ResourceGroup: "rg2"},
			},
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				domainsClient := &mockAFDCustomDomainsClient{}
				pager1 := &mockAFDCustomDomainsPager{}
				pager2 := &mockAFDCustomDomainsPager{}

				resp1 := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: []*armcdn.AFDDomain{
							{Properties: &armcdn.AFDDomainProperties{HostName: to.Ptr("example1.com")}},
							{Properties: &armcdn.AFDDomainProperties{HostName: to.Ptr("example2.com")}},
						},
					},
				}
				resp2 := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: []*armcdn.AFDDomain{
							{Properties: &armcdn.AFDDomainProperties{HostName: to.Ptr("example3.com")}},
						},
					},
				}

				pager1.On("More").Return(true).Once()
				pager1.On("More").Return(false).Once()
				pager1.On("NextPage", mock.Anything).Return(resp1, nil).Once()

				pager2.On("More").Return(true).Once()
				pager2.On("More").Return(false).Once()
				pager2.On("NextPage", mock.Anything).Return(resp2, nil).Once()

				domainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(pager1)
				domainsClient.On("NewListByProfilePager", "rg2", "profile2", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(pager2)
				factory.On("NewAFDCustomDomainsClient").Return(domainsClient)
				return factory
			},
			want: []string{"example1.com", "example2.com", "example3.com"},
		},
		{
			name:     "no profiles provided",
			profiles: []AFDProfile{},
			setupMocks: func() *mockClientFactory {
				return &mockClientFactory{}
			},
			want: nil,
		},
		{
			name:     "profile with no custom domains",
			profiles: []AFDProfile{{Name: "profile1", ResourceGroup: "rg1"}},
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				domainsClient := &mockAFDCustomDomainsClient{}
				pager := &mockAFDCustomDomainsPager{}

				resp := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{Value: []*armcdn.AFDDomain{}},
				}

				pager.On("More").Return(true).Once()
				pager.On("More").Return(false).Once()
				pager.On("NextPage", mock.Anything).Return(resp, nil).Once()
				domainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(pager)
				factory.On("NewAFDCustomDomainsClient").Return(domainsClient)
				return factory
			},
			want: nil,
		},
		{
			name:     "domains with nil properties skipped",
			profiles: []AFDProfile{{Name: "profile1", ResourceGroup: "rg1"}},
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				domainsClient := &mockAFDCustomDomainsClient{}
				pager := &mockAFDCustomDomainsPager{}

				resp := armcdn.AFDCustomDomainsClientListByProfileResponse{
					AFDDomainListResult: armcdn.AFDDomainListResult{
						Value: []*armcdn.AFDDomain{
							{Properties: nil},
							{Properties: &armcdn.AFDDomainProperties{HostName: nil}},
							{Properties: &armcdn.AFDDomainProperties{HostName: to.Ptr("valid.com")}},
						},
					},
				}

				pager.On("More").Return(true).Once()
				pager.On("More").Return(false).Once()
				pager.On("NextPage", mock.Anything).Return(resp, nil).Once()
				domainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(pager)
				factory.On("NewAFDCustomDomainsClient").Return(domainsClient)
				return factory
			},
			want: []string{"valid.com"},
		},
		{
			name:     "pagination error",
			profiles: []AFDProfile{{Name: "profile1", ResourceGroup: "rg1"}},
			setupMocks: func() *mockClientFactory {
				factory := &mockClientFactory{}
				domainsClient := &mockAFDCustomDomainsClient{}
				pager := &mockAFDCustomDomainsPager{}

				pager.On("More").Return(true).Once()
				pager.On("NextPage", mock.Anything).Return(armcdn.AFDCustomDomainsClientListByProfileResponse{}, errors.New("pagination failed"))
				domainsClient.On("NewListByProfilePager", "rg1", "profile1", (*armcdn.AFDCustomDomainsClientListByProfileOptions)(nil)).Return(pager)
				factory.On("NewAFDCustomDomainsClient").Return(domainsClient)
				return factory
			},
			want:    nil,
			wantErr: "failed to advance page in getAFDCustomDomains : pagination failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			factory := tt.setupMocks()
			ctx := context.Background()

			result, err := getAFDCustomDomains(factory, tt.profiles, ctx)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
			factory.AssertExpectations(t)
		})
	}
}

func TestFormatBulletList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		items []string
		want  string
	}{
		{
			name:  "single item",
			items: []string{"a.example.com -> a.blob.core.windows.net"},
			want:  "• a.example.com -> a.blob.core.windows.net",
		},
		{
			name:  "multiple items",
			items: []string{"a.example.com -> a.blob.core.windows.net", "b.example.com -> b.azurewebsites.net"},
			want:  "• a.example.com -> a.blob.core.windows.net\n• b.example.com -> b.azurewebsites.net",
		},
		{
			name:  "empty list",
			items: []string{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := formatBulletList(tt.items)
			assert.Equal(t, tt.want, got)
		})
	}
}

func BenchmarkContainsAzureVulnerableResources(b *testing.B) {
	testResource := "myapp.azurewebsites.net"
	b.ResetTimer()
	for range b.N {
		containsAzureVulnerableResources(testResource)
	}
}

func BenchmarkIsVulnerableResource(b *testing.B) {
	resources := make(map[string]struct{})
	for i := range 1000 {
		resources[fmt.Sprintf("resource%d.azurewebsites.net", i)] = struct{}{}
	}
	testCname := "test.azurewebsites.net"
	b.ResetTimer()
	for range b.N {
		isVulnerableResource(resources, testCname)
	}
}
