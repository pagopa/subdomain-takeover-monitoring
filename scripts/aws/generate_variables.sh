#!/bin/bash
set -e

echo "🔗 Generating random ZoneId and ZoneName..."
RANDOM_STR=$(openssl rand -hex 6)
DNS_ZONE="${RANDOM_STR}.net"
SUBDOMAIN_AND_S3_NAME="subdomain.${DNS_ZONE}"
echo "dns_zone=$DNS_ZONE" >> $GITHUB_ENV
echo "subdomain_and_s3_name=$SUBDOMAIN_AND_S3_NAME" >> $GITHUB_ENV
echo "✅ ZoneId and ZoneName created correctly."