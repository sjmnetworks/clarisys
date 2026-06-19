# --- IAM Roles for ECS -----------------------------------------------------

# Task execution role (ECR pull, CloudWatch logs)
resource "aws_iam_role" "ecs_execution" {
  name = "${var.project_name}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.project_name}-ecs-execution" }
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow ECS execution role to read secrets (JWT_SECRET, API keys)
resource "aws_iam_role_policy" "ecs_execution_secrets" {
  count = var.jwt_secret_arn != "" || var.api_key_secret_arn != "" ? 1 : 0
  name  = "${var.project_name}-secrets-read"
  role  = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = compact([
          var.jwt_secret_arn,
          var.api_key_secret_arn,
        ])
      }
    ]
  })
}

# Task role (S3 access for audit backend, EFS)
resource "aws_iam_role" "ecs_task" {
  name = "${var.project_name}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.project_name}-ecs-task" }
}

# S3 audit bucket access
resource "aws_iam_role_policy" "ecs_task_s3" {
  count = var.enable_s3_audit ? 1 : 0
  name  = "${var.project_name}-s3-audit"
  role  = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetObjectRetention",
          "s3:PutObjectRetention"
        ]
        Resource = [
          aws_s3_bucket.audit[0].arn,
          "${aws_s3_bucket.audit[0].arn}/*"
        ]
      }
    ]
  })
}

# EFS access
resource "aws_iam_role_policy" "ecs_task_efs" {
  name = "${var.project_name}-efs"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:ClientRootAccess"
        ]
        Resource = aws_efs_file_system.state.arn
      }
    ]
  })
}
