#!/bin/bash
set -e

echo "🔗 Creating zone on Route53..."
CALLER_REF=$(openssl rand -hex 6)
aws route53 create-hosted-zone --name $dns_zone --caller-reference ${CALLER_REF}> zone.json
ZONE_ID=$(jq -r '.HostedZone.Id' zone.json | cut -d'/' -f3)
echo "zone_id=$ZONE_ID" >> $GITHUB_ENV
echo "✅ Zone on Route53 created correctly."