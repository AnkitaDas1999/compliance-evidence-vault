#!/bin/bash
# run_fargate_task.sh
# Manually triggers a SAST or Pentest Fargate task against
# Ishit's real VPC.
#
# Prerequisites:
#   1. terraform apply completed (so ECR + task defs exist)
#   2. Docker images pushed to ECR
#   3. S3 bucket exists (create_s3_lifecycle.sh was run)
#   4. RDS is up (Ishit's infra) — OR use DB_SSLMODE=disable with a test job
#
# Usage:
#   ./run_fargate_task.sh sast
#   ./run_fargate_task.sh pentest

set -euo pipefail

MODE="${1:?Usage: $0 sast|pentest}"
REGION="us-east-1"
ACCOUNT_ID="126573932591"
CLUSTER="compliance-vault-compute-cluster"
BUCKET="compliance-vault-reports"
JOB_ID="demo-$(date +%s)"

# Ishit's networking
VPC_ID="vpc-02eb7b9eda9780a61"
SUBNET_A="subnet-0bc64a67fcb07b394"
SUBNET_B="subnet-06b2f4ec1682a750e"
FARGATE_SG="sg-0e6a3282012c9d80c"
LAB_ROLE="arn:aws:iam::$ACCOUNT_ID:role/LabRole"

echo "=================================================="
echo " Running $MODE Fargate task"
echo " Job ID: $JOB_ID"
echo "=================================================="
echo ""

if [ "$MODE" = "sast" ]; then
  TASK_FAMILY="compliance-vault-compute-sast"

  # Upload a test zip to S3 and generate a pre-signed URL
  echo "=== Uploading test zip to S3 ==="
  cd "$(dirname "$0")"
  zip /tmp/test-upload-$JOB_ID.zip sample_vulnerable_app.py
  aws s3 cp /tmp/test-upload-$JOB_ID.zip \
    s3://$BUCKET/uploads/$JOB_ID/source.zip
  PRESIGNED_URL=$(aws s3 presign \
    s3://$BUCKET/uploads/$JOB_ID/source.zip \
    --expires-in 3600)
  echo "  Pre-signed URL generated (expires in 1h)"

  ENV_OVERRIDES="[
    {\"name\": \"JOB_ID\",           \"value\": \"$JOB_ID\"},
    {\"name\": \"S3_PRESIGNED_URL\",  \"value\": \"$PRESIGNED_URL\"},
    {\"name\": \"REPORT_BUCKET\",     \"value\": \"$BUCKET\"},
    {\"name\": \"DB_HOST\",           \"value\": \"placeholder-rds\"},
    {\"name\": \"DB_NAME\",           \"value\": \"vault\"},
    {\"name\": \"DB_USER\",           \"value\": \"vaultuser\"},
    {\"name\": \"DB_PASSWORD\",       \"value\": \"placeholder\"},
    {\"name\": \"DB_SSLMODE\",        \"value\": \"disable\"}
  ]"
  CONTAINER_NAME="sast-scanner"

elif [ "$MODE" = "pentest" ]; then
  TASK_FAMILY="compliance-vault-compute-pentest"
  TARGET_URL="https://example.com"   # safe public target for demo

  ENV_OVERRIDES="[
    {\"name\": \"JOB_ID\",        \"value\": \"$JOB_ID\"},
    {\"name\": \"TARGET_URL\",    \"value\": \"$TARGET_URL\"},
    {\"name\": \"REPORT_BUCKET\", \"value\": \"$BUCKET\"},
    {\"name\": \"DB_HOST\",       \"value\": \"placeholder-rds\"},
    {\"name\": \"DB_NAME\",       \"value\": \"vault\"},
    {\"name\": \"DB_USER\",       \"value\": \"vaultuser\"},
    {\"name\": \"DB_PASSWORD\",   \"value\": \"placeholder\"},
    {\"name\": \"DB_SSLMODE\",    \"value\": \"disable\"}
  ]"
  CONTAINER_NAME="pentest-scanner"
fi

# Get the latest task definition ARN
TASK_DEF_ARN=$(aws ecs list-task-definitions \
  --family-prefix $TASK_FAMILY \
  --sort DESC \
  --query "taskDefinitionArns[0]" \
  --output text --region $REGION)
echo "Using task definition: $TASK_DEF_ARN"
echo ""

echo "=== Running Fargate task ==="
TASK_ARN=$(aws ecs run-task \
  --cluster $CLUSTER \
  --task-definition $TASK_DEF_ARN \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[$SUBNET_A,$SUBNET_B],
    securityGroups=[$FARGATE_SG],
    assignPublicIp=DISABLED
  }" \
  --overrides "{
    \"containerOverrides\": [{
      \"name\": \"$CONTAINER_NAME\",
      \"environment\": $ENV_OVERRIDES
    }],
    \"executionRoleArn\": \"$LAB_ROLE\",
    \"taskRoleArn\":      \"$LAB_ROLE\"
  }" \
  --region $REGION \
  --query "tasks[0].taskArn" \
  --output text)

echo "  Task ARN: $TASK_ARN"
TASK_ID=$(echo $TASK_ARN | cut -d'/' -f3)
echo "  Task ID:  $TASK_ID"
echo ""

echo "=== Waiting for task to finish (polls every 10s) ==="
for i in $(seq 1 30); do
  STATUS=$(aws ecs describe-tasks \
    --cluster $CLUSTER \
    --tasks $TASK_ARN \
    --query "tasks[0].lastStatus" \
    --output text --region $REGION)
  echo "  [$i] Status: $STATUS"
  if [ "$STATUS" = "STOPPED" ]; then
    break
  fi
  sleep 10
done

echo ""
echo "=== Final task status ==="
aws ecs describe-tasks \
  --cluster $CLUSTER \
  --tasks $TASK_ARN \
  --query "tasks[0].{Status:lastStatus,StopCode:stopCode,StoppedReason:stoppedReason,StartedAt:startedAt,StoppedAt:stoppedAt}" \
  --output table --region $REGION

echo ""
echo "=== CloudWatch logs (last 20 lines) ==="
LOG_GROUP="/ecs/compliance-vault-compute/$MODE-scanner"
LOG_STREAM="ecs/$CONTAINER_NAME/$TASK_ID"

# Give logs a moment to flush
sleep 5
aws logs get-log-events \
  --log-group-name $LOG_GROUP \
  --log-stream-name $LOG_STREAM \
  --limit 20 \
  --query "events[*].message" \
  --output text --region $REGION 2>/dev/null || echo "  (logs not yet available — check Console in 30s)"

echo ""
echo "=== S3 report ==="
aws s3 ls s3://$BUCKET/reports/$MODE/$JOB_ID/ 2>/dev/null || \
  echo "  (task may have exited before writing report — check logs above)"

echo ""
echo "=== Console links (open in browser) ==="
echo "  ECS Task:   https://console.aws.amazon.com/ecs/v2/clusters/$CLUSTER/tasks/$TASK_ID/configuration?region=$REGION"
echo "  CW Logs:    https://console.aws.amazon.com/cloudwatch/home?region=$REGION#logsV2:log-groups/log-group/\$252Fecs\$252Fcompliance-vault-compute\$252F$MODE-scanner"
echo "  S3 Report:  https://s3.console.aws.amazon.com/s3/buckets/$BUCKET?region=$REGION&prefix=reports/$MODE/$JOB_ID/"