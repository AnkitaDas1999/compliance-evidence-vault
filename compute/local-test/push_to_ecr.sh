#!/bin/bash
# push_to_ecr.sh
# Builds both scanner images and pushes to ECR
# Run after `terraform apply` in compute/terraform/
#
# Usage:
#   ./push_to_ecr.sh <aws-account-id> <aws-region>
#   ./push_to_ecr.sh 126573932591 us-east-1

set -euo pipefail

ACCOUNT_ID="${1:?Usage: $0 <account-id> <region>}"
REGION="${2:-us-east-1}"
PROJECT="compliance-vault-compute"

SAST_REPO="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$PROJECT-sast-scanner"
PENTEST_REPO="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$PROJECT-pentest-scanner"

echo "=== Authenticating with ECR ==="
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"

echo ""
echo "=== Building SAST scanner ==="
docker build -t sast-scanner:latest ../sast-scanner/
docker tag sast-scanner:latest "$SAST_REPO:latest"
docker push "$SAST_REPO:latest"
echo "Pushed: $SAST_REPO:latest"

echo ""
echo "=== Building Pentest scanner ==="
docker build -t pentest-scanner:latest ../pentest-scanner/
docker tag pentest-scanner:latest "$PENTEST_REPO:latest"
docker push "$PENTEST_REPO:latest"
echo "Pushed: $PENTEST_REPO:latest"

echo ""
echo "=== Done ==="
echo "SAST image:    $SAST_REPO:latest"
echo "Pentest image: $PENTEST_REPO:latest"
echo ""
echo "=== Verifying images in ECR ==="
for repo in $PROJECT-sast-scanner $PROJECT-pentest-scanner; do
  echo "  $repo:"
  aws ecr describe-images \
    --repository-name $repo \
    --query "imageDetails[*].{Tag:imageTags[0],Pushed:imagePushedAt,SizeMB:imageSizeInBytes}" \
    --output table --region $REGION
done

echo ""
echo "Next: verify ECR scan results (scan_on_push=true, takes ~30s)"
echo "  aws ecr describe-image-scan-findings --repository-name $PROJECT-sast-scanner --image-id imageTag=latest --region $REGION"