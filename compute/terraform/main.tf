# ===========================================================================
# Terraform module — Compute layer
# ECS Fargate task definitions + ECR image management + S3 lifecycle policy
#
# Depends on:
#   - var.vpc_id, var.private_subnet_ids  (Ishit's VPC module outputs)
#   - var.rds_security_group_id           (Ishit's VPC module outputs)
#   - var.report_bucket_name              (passed in from root module)
# ===========================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "aws_region"            { default = "us-east-1" }
variable "project"               { default = "compliance-vault" }
variable "vpc_id"                { description = "VPC ID from Ishit's module" }
variable "private_subnet_ids"    { description = "Private subnet IDs", type = list(string) }
variable "rds_security_group_id" { description = "RDS SG — scanners need outbound 5432 to it" }
variable "report_bucket_name"    { description = "S3 bucket for report uploads" }
variable "ecr_image_tag"         { default = "latest" }

locals {
  prefix = "${var.project}-compute"
}

# ---------------------------------------------------------------------------
# ECR repositories
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "sast" {
  name                 = "${local.prefix}-sast-scanner"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true   # free basic ECR scanning
  }

  tags = { Component = "ankita-compute" }
}

resource "aws_ecr_repository" "pentest" {
  name                 = "${local.prefix}-pentest-scanner"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Component = "ankita-compute" }
}

# Lifecycle policy — keep only the last 10 images to control costs
resource "aws_ecr_lifecycle_policy" "sast" {
  repository = aws_ecr_repository.sast.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "pentest" {
  repository = aws_ecr_repository.pentest.name
  policy     = aws_ecr_lifecycle_policy.sast.policy
}

# ---------------------------------------------------------------------------
# IAM — ECS task execution role (pull from ECR, write CloudWatch logs)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "ecs_execution" {
  name = "${local.prefix}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ---------------------------------------------------------------------------
# IAM — ECS task role (scanner runtime permissions: S3 write, SSM read)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "ecs_task" {
  name = "${local.prefix}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# S3 — write to reports/ prefix only (least privilege)
resource "aws_iam_role_policy" "scanner_s3" {
  name = "scanner-s3-write"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteReports"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:PutObjectAcl"]
        Resource = "arn:aws:s3:::${var.report_bucket_name}/reports/*"
      },
      {
        Sid    = "ReadUploads"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = "arn:aws:s3:::${var.report_bucket_name}/uploads/*"
      }
    ]
  })
}

# SSM Parameter Store — read DB credentials
resource "aws_iam_role_policy" "scanner_ssm" {
  name = "scanner-ssm-read"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameter", "ssm:GetParameters"]
      Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/${var.project}/*"
    }]
  })
}

# ---------------------------------------------------------------------------
# Security group for scanner tasks
# ---------------------------------------------------------------------------

resource "aws_security_group" "scanner" {
  name        = "${local.prefix}-scanner-sg"
  description = "ECS Fargate scanner tasks"
  vpc_id      = var.vpc_id

  # Outbound: HTTPS to pull images, reach S3/SSM via VPC endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS out — ECR, S3, SSM"
  }

  # Outbound: PostgreSQL to RDS SG only
  egress {
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = var.rds_security_group_id
    description              = "PostgreSQL to RDS"
  }

  # No inbound — Fargate tasks are outbound-only workers
  tags = { Component = "ankita-compute" }
}

# ---------------------------------------------------------------------------
# CloudWatch log groups
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
    value = "enabled"   # needed for CloudWatch CPU/memory metrics
  }

  tags = { Component = "ankita-compute" }
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
# ECS task definitions
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "sast" {
  family                   = "${local.prefix}-sast"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "sast-scanner"
    image     = "${aws_ecr_repository.sast.repository_url}:${var.ecr_image_tag}"
    essential = true

    environment = []   # non-secret config here if needed

    # Secrets injected at runtime by Step Functions via ECS overrides:
    # JOB_ID, S3_PRESIGNED_URL, REPORT_BUCKET, DB_HOST, DB_NAME, DB_USER, DB_PASSWORD

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.sast.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }

    # Read-only root filesystem (security hardening)
    readonlyRootFilesystem = false   # scanner needs /tmp for zip extraction
    user                   = "scanner"
  }])

  tags = { Component = "ankita-compute" }
}

resource "aws_ecs_task_definition" "pentest" {
  family                   = "${local.prefix}-pentest"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "pentest-scanner"
    image     = "${aws_ecr_repository.pentest.repository_url}:${var.ecr_image_tag}"
    essential = true

    environment = []

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.pentest.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }

    user = "scanner"
  }])

  tags = { Component = "ankita-compute" }
}

# ---------------------------------------------------------------------------
# S3 lifecycle policy — Standard → Glacier after 90 days
# ---------------------------------------------------------------------------

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = var.report_bucket_name

  rule {
    id     = "reports-archive"
    status = "Enabled"

    filter {
      prefix = "reports/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555   # 7-year retention (SOC2 / HIPAA common requirement)
    }
  }

  rule {
    id     = "uploads-cleanup"
    status = "Enabled"

    filter {
      prefix = "uploads/"
    }

    expiration {
      days = 7   # raw uploads don't need long-term retention
    }
  }
}

# ---------------------------------------------------------------------------
# Outputs (consumed by Ishit's Step Functions module)
# ---------------------------------------------------------------------------

output "sast_task_definition_arn"   { value = aws_ecs_task_definition.sast.arn }
output "pentest_task_definition_arn" { value = aws_ecs_task_definition.pentest.arn }
output "ecs_cluster_arn"            { value = aws_ecs_cluster.scanners.arn }
output "scanner_security_group_id"  { value = aws_security_group.scanner.id }
output "sast_ecr_url"               { value = aws_ecr_repository.sast.repository_url }
output "pentest_ecr_url"            { value = aws_ecr_repository.pentest.repository_url }
