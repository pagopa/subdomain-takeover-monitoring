package selftest

import (
	"strings"
	"testing"
)

func TestAWSCanaryMatches(t *testing.T) {
	canary := AWSCanary{
		DNSZone:    "ab12cd34ef56.net",
		BucketName: "subdomain.ab12cd34ef56.net",
	}

	tests := []struct {
		TestName string
		Item     string
		Want     bool
	}{
		{
			TestName: "matches by record name",
			Item:     "subdomain.ab12cd34ef56.net -> subdomain.ab12cd34ef56.net.s3.eu-south-1.amazonaws.com",
			Want:     true,
		},
		{
			TestName: "matches by zone only",
			Item:     "www.ab12cd34ef56.net -> something.s3.eu-south-1.amazonaws.com",
			Want:     true,
		},
		{
			TestName: "does not match a different zone",
			Item:     "images.example.com -> images.example.com.s3.us-east-1.amazonaws.com",
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

func TestAWSCanarySplit(t *testing.T) {
	canary := AWSCanary{
		DNSZone:    "ab12cd34ef56.net",
		BucketName: "subdomain.ab12cd34ef56.net",
	}
	canaryItem := "subdomain.ab12cd34ef56.net -> subdomain.ab12cd34ef56.net.s3.eu-south-1.amazonaws.com"
	realItem1 := "images.example.com -> images.example.com.s3.us-east-1.amazonaws.com"
	realItem2 := "app.example.org -> app.eu-south-1.elasticbeanstalk.com"

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

func equalStringSlices(a, b []string) bool {
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

func TestGenerateAWSNames(t *testing.T) {
	dnsZone, bucketName, err := generateAWSNames()
	if err != nil {
		t.Fatalf("generateAWSNames returned error: %v", err)
	}

	tests := []struct {
		TestName string
		Check    func(t *testing.T)
	}{
		{
			TestName: "dns zone ends with .net",
			Check: func(t *testing.T) {
				if !strings.HasSuffix(dnsZone, ".net") {
					t.Errorf("dnsZone = %q, want suffix .net", dnsZone)
				}
			},
		},
		{
			TestName: "hex label has 12 characters",
			Check: func(t *testing.T) {
				label := strings.TrimSuffix(dnsZone, ".net")
				if len(label) != 12 {
					t.Errorf("hex label = %q (len %d), want len 12", label, len(label))
				}
			},
		},
		{
			TestName: "bucket name derives from dns zone",
			Check: func(t *testing.T) {
				if bucketName != "subdomain."+dnsZone {
					t.Errorf("bucketName = %q, want %q", bucketName, "subdomain."+dnsZone)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, tt.Check)
	}
}
