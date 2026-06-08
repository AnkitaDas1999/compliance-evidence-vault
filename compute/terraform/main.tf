# ===========================================================================
# Terraform module — Compute layer
# ECS Fargate task definitions + ECR repos + S3 lifecycle policy
#
# Wired to Ishit's VPC: vpc-02eb7b9eda9780a61 (us-east-1, acct 126573932591)
# ===========================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "aws_region"                 { default = "us-east-1" }
variable "project"                    { default = "compliance-vault" }
# variable "vpc_id"                     { description = "Ishit's VPC ID" }
# variable "private_subnet_ids"         { type = list(string) }
# variable "rds_security_group_id"      { description = "Ishit's RDS SG — scanners send outbound 5432 to it" }
# variable "fargate_security_group_id"  { description = "Ishit's Fargate SG" }
variable "report_bucket_name"         { description = "S3 bucket for report uploads" }
variable "ecr_image_tag"              { default = "latest" }

locals {
  prefix   = "${var.project}-compute"
  # AWS Academy LabRole — used instead of creating IAM roles
  lab_role = "arn:aws:iam::126573932591:role/LabRole"
}

# ---------------------------------------------------------------------------
# ECR repositories
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "sast" {
  name                 = "${local.prefix}-sast-scanner"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Component = "ankita-compute", Owner = "ankita" }
}

resource "aws_ecr_repository" "pentest" {
  name                 = "${local.prefix}-pentest-scanner"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Component = "ankita-compute", Owner = "ankita" }
}

# Keep only the last 10 images to avoid storage costs
resource "aws_ecr_lifecycle_policy" "sast" {
  repository = aws_ecr_repository.sast.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10 }
      action       = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "pentest" {
  repository = aws_ecr_repository.pentest.name
  policy     = aws_ecr_lifecycle_policy.sast.policy
}

# ---------------------------------------------------------------------------
# CloudWatch log groups (Ankita owns these)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "sast" {
  name              = "/ecs/${local.prefix}/sast-scanner"
  retention_in_days = 30
  tags              = { Component = "ankita-compute" }
}

resource "aws_cloudwatch_log_group" "pentest" {
  name              = "/ecs/${local.prefix}/pentest-scanner"
  retention_in_days = 30
  tags              = { Component = "ankita-compute" }
}

# ---------------------------------------------------------------------------
# ECS cluster
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "scanners" {
  name = "${local.prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Component = "ankita-compute", Owner = "ankita" }
}

resource "aws_ecs_cluster_capacity_providers" "scanners" {
  cluster_name       = aws_ecs_cluster.scanners.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ---------------------------------------------------------------------------
# ECS task definitions (using LabRole — no new IAM roles needed)
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "sast" {
  family                   = "${local.prefix}-sast"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = local.lab_role
  task_role_arn            = local.lab_role

  container_definitions = jsonencode([{
    name      = "sast-scanner"
    image     = "${aws_ecr_repository.sast.repository_url}:${var.ecr_image_tag}"
    essential = true

    # JOB_ID and S3_PRESIGNED_URL are injected at runtime
    # by Step Functions via container environment overrides
    environment = [
      { name = "REPORT_BUCKET", value = var.report_bucket_name },
      { name = "DB_SSLMODE",    value = "require" }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.sast.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Component = "ankita-compute", Owner = "ankita" }
}

resource "aws_ecs_task_definition" "pentest" {
  family                   = "${local.prefix}-pentest"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = local.lab_role
  task_role_arn            = local.lab_role

  container_definitions = jsonencode([{
    name      = "pentest-scanner"
    image     = "${aws_ecr_repository.pentest.repository_url}:${var.ecr_image_tag}"
    essential = true

    environment = [
      { name = "REPORT_BUCKET", value = var.report_bucket_name },
      { name = "DB_SSLMODE",    value = "require" }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.pentest.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Component = "ankita-compute", Owner = "ankita" }
}

# ---------------------------------------------------------------------------
# S3 lifecycle policy — Standard → Glacier after 90 days
# ---------------------------------------------------------------------------

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = var.report_bucket_name

  rule {
    id     = "reports-archive"
    status = "Enabled"
    filter { prefix = "reports/" }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = 2555   # 7-year retention for SOC2/HIPAA
    }
  }

  rule {
    id     = "uploads-cleanup"
    status = "Enabled"
    filter { prefix = "uploads/" }
    expiration { days = 7 }
  }
}

# ---------------------------------------------------------------------------
# Outputs — shared with Ishit for Step Functions integration
# ---------------------------------------------------------------------------

output "sast_task_definition_arn" {
  value       = aws_ecs_task_definition.sast.arn
  description = "Pass to Ishit for Step Functions ECS task ARN"
}

output "pentest_task_definition_arn" {
  value       = aws_ecs_task_definition.pentest.arn
  description = "Pass to Ishit for Step Functions ECS task ARN"
}

output "ecs_cluster_arn" {
  value       = aws_ecs_cluster.scanners.arn
  description = "Pass to Ishit for Step Functions cluster ARN"
}

output "sast_ecr_url" {
  value = aws_ecr_repository.sast.repository_url
}

output "pentest_ecr_url" {
  value = aws_ecr_repository.pentest.repository_url
}

output "sast_log_group" {
  value = aws_cloudwatch_log_group.sast.name
}

output "pentest_log_group" {
  value = aws_cloudwatch_log_group.pentest.name
}
