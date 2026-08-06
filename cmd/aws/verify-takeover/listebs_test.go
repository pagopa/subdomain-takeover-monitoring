package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebsTypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

type mockEBSClient struct {
	output *elasticbeanstalk.DescribeEnvironmentsOutput
	err    error
}

func (m *mockEBSClient) DescribeEnvironments(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestListEBSEnvironment(t *testing.T) {
	tests := []struct {
		TestName string
		Client   *mockEBSClient
		Want     map[string]bool
		WantErr  bool
	}{
		{
			TestName: "keeps active CNAMEs and skips terminated or nil",
			Client: &mockEBSClient{output: &elasticbeanstalk.DescribeEnvironmentsOutput{
				Environments: []ebsTypes.EnvironmentDescription{
					{CNAME: aws.String("Active.eu-south-1.elasticbeanstalk.com"), Status: ebsTypes.EnvironmentStatusReady},
					{CNAME: aws.String("gone.eu-south-1.elasticbeanstalk.com"), Status: ebsTypes.EnvironmentStatusTerminated},
					{CNAME: nil, Status: ebsTypes.EnvironmentStatusReady},
				},
			}},
			Want: map[string]bool{
				"active.eu-south-1.elasticbeanstalk.com": true, // lowercased
			},
		},
		{
			TestName: "no environments yields empty set",
			Client:   &mockEBSClient{output: &elasticbeanstalk.DescribeEnvironmentsOutput{}},
			Want:     map[string]bool{},
		},
		{
			TestName: "describe error is returned",
			Client:   &mockEBSClient{err: errors.New("boom")},
			WantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			got := make(map[string]bool)
			err := listEBSEnvironment(tt.Client, got)
			if tt.WantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.Want) {
				t.Fatalf("got %v, want %v", got, tt.Want)
			}
			for k := range tt.Want {
				if !got[k] {
					t.Errorf("missing key %q in %v", k, got)
				}
			}
		})
	}
}
