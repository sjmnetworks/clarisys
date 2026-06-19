# --- ECS Cluster + Service + Task Definition --------------------------------

resource "aws_ecs_cluster" "main" {
  name = var.project_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${var.project_name}-cluster" }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 30

  tags = { Name = "${var.project_name}-logs" }
}

resource "aws_ecs_task_definition" "api" {
  family                   = var.project_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  volume {
    name = "state"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.state.id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.app.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = "${aws_ecr_repository.api.repository_url}:latest"
      essential = true

      portMappings = [{
        containerPort = 8000
        protocol      = "tcp"
      }]

      environment = [
        { name = "APP_ENV", value = "production" },
        { name = "OPA_BINARY", value = "/usr/local/bin/opa" },
        { name = "OPA_HOST", value = "127.0.0.1" },
        { name = "OPA_PORT", value = "8181" },
        { name = "AUTH_ENABLED", value = "true" },
        { name = "AUDIT_BACKEND", value = var.enable_s3_audit ? "s3" : "local" },
        { name = "AUDIT_S3_BUCKET", value = var.enable_s3_audit ? aws_s3_bucket.audit[0].id : "" },
        { name = "AUDIT_S3_PREFIX", value = "audit/" },
        { name = "AUDIT_S3_OBJECT_LOCK_MODE", value = "GOVERNANCE" },
        { name = "DECISION_HISTORY_FILE", value = "/mnt/state/decision_history.jsonl" },
        { name = "DECISION_LIFECYCLE_FILE", value = "/mnt/state/decision_lifecycle.json" },
        { name = "USERS_FILE", value = "/mnt/state/users.json" },
        { name = "PILOT_USERS_FILE", value = "/mnt/state/pilot_users.json" },
        { name = "EVIDENCE_DIR", value = "/mnt/state/evidence" },
        { name = "RATE_LIMIT_ENABLED", value = "true" },
        { name = "RATE_LIMIT_WINDOW_SECS", value = "60" },
        { name = "RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", value = "100" },
        { name = "RATE_LIMIT_QUOTA_BULK_PER_MIN", value = "20" },
        { name = "RATE_LIMIT_QUOTA_AUDIT_PER_MIN", value = "10" },
        { name = "LOG_LEVEL", value = "INFO" },
      ]

      secrets = var.jwt_secret_arn != "" ? [
        { name = "JWT_SECRET", valueFrom = var.jwt_secret_arn },
      ] : []

      mountPoints = [{
        sourceVolume  = "state"
        containerPath = "/mnt/state"
        readOnly      = false
      }]

      dependsOn = [{
        containerName = "opa"
        condition     = "HEALTHY"
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "api"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health')\""]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }
    },
    {
      name      = "opa"
      image     = "${aws_ecr_repository.api.repository_url}:latest"
      essential = true

      entryPoint = ["/usr/local/bin/opa"]
      command    = [
        "run", "--server", "--addr", "0.0.0.0:8181",
        "/app/policy/firewall.rego",
        "/app/policy/firewall_compliance.rego",
        "/app/policy/integrated_compliance.rego",
        "/app/policy/nfr_compliance.rego",
        "/app/policy/request_standards.rego",
        "/app/policy/request_standards_batch.rego",
        "/app/policy/data.json"
      ]

      portMappings = [{
        containerPort = 8181
        protocol      = "tcp"
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "opa"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8181/health')\""]
        interval    = 10
        timeout     = 5
        retries     = 3
        startPeriod = 5
      }
    }
  ])

  tags = { Name = "${var.project_name}-task" }
}

resource "aws_ecs_service" "api" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [
    aws_lb_listener.http,
    aws_efs_mount_target.state,
  ]

  tags = { Name = "${var.project_name}-service" }
}
