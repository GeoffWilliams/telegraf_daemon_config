# enpoints to allow ECS to access secretsmanager, ECR and cloudwatch (essential if in private subnet)
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.ap-southeast-2.secretsmanager"
  vpc_endpoint_type = "Interface"
  subnet_ids = [
    aws_subnet.private-a.id,
    aws_subnet.private-b.id,
  ]
  security_group_ids = [
    aws_security_group.private-access.id,
  ]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.ap-southeast-2.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids = [
    aws_subnet.private-a.id,
    aws_subnet.private-b.id,
  ]
  security_group_ids = [
    aws_security_group.private-access.id,
  ]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.ap-southeast-2.ecr.dkr"
  vpc_endpoint_type = "Interface"
  subnet_ids = [
    aws_subnet.private-a.id,
    aws_subnet.private-b.id,
  ]
  security_group_ids = [
    aws_security_group.private-access.id,
  ]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "cloudwatch" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.ap-southeast-2.logs"
  vpc_endpoint_type = "Interface"
  subnet_ids = [
    aws_subnet.private-a.id,
    aws_subnet.private-b.id,
  ]
  security_group_ids = [
    aws_security_group.private-access.id,
  ]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.ap-southeast-2.s3"
  route_table_ids = [aws_route_table.private.id]
}

# secrets required by ECS task (for illustration)
resource "aws_secretsmanager_secret" "postgres" {
  name = "gwilliams/postgres"
}

resource "aws_secretsmanager_secret_version" "postgres" {
  secret_id     = aws_secretsmanager_secret.postgres.id
  secret_string = jsonencode({
      URL: "postgresql://..."
  })
}

# secrets for kafka metrics
resource "aws_secretsmanager_secret" "ccloud_metrics_api" {
  name = "gwilliams/ccloud_metrics_api"
  description = "confluent cloud metrics gwilliams - CCLOUD_METRICS_API_KEY + CCLOUD_METRICS_API_SECRET"
}

resource "aws_secretsmanager_secret_version" "ccloud_metrics_api" {
  secret_id     = aws_secretsmanager_secret.ccloud_metrics_api.id
  secret_string = jsonencode({
    "CCLOUD_API_KEY": "akeyid",
    "CCLOUD_API_SECRET": "asecretvalue"
  })
}


#
# Metrics support
#

# ECS access to secretsmanager and cloudwatch
resource "aws_iam_policy" "ecs_access" {
  name        = "ecs_access_gwilliams"
  path        = "/"
  description = "Access to secretsmanager and cloudwatch for ECS"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Effect   = "Allow"
        Resource = [ 
          aws_secretsmanager_secret.ccloud_metrics_api.arn,
          aws_secretsmanager_secret_version.postgres.arn
        ]
      },
      {
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Effect = "Allow"
        Resource = [
          "*"
        ]
      }
    ]
  })
}

# combined execution and task role
# execution role uses the AWS manage policy and is required for access to ECR
# and a self-managed policy to access secretsmanager for confluent cloud credentials
resource "aws_iam_role" "ecs_role" {
  name                = "${var.lab_name}-ecs-role"
  path                = "/"
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    aws_iam_policy.ecs_access.arn
  ]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "",
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })
}



# a blank cluster
resource "aws_ecs_cluster" "cluster" {
  name = "gwilliams-ecs-cluster"
}

# cluster should use fargate
resource "aws_ecs_cluster_capacity_providers" "fargate" {
  cluster_name = aws_ecs_cluster.cluster.name

  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "ecs_task" {
  name = "/ecs/gwilliams-telegraf-task"  
}

# define our task
resource "aws_ecs_task_definition" "telegraf_agent" {
  family                   = "telegraf-agent-gwilliams"
  execution_role_arn       = aws_iam_role.ecs_role.arn
  task_role_arn            = aws_iam_role.ecs_role.arn
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  
  # see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html
  cpu                      = 256
  memory                   = 512
  runtime_platform {
    operating_system_family = "LINUX"
  }
  container_definitions    = jsonencode([
    {
      "name": "telegraf-agent-container-gwilliams",
      "image": "REPLACE_WITH_ECR_IMAGE_TAG",
      "cpu": 256,
      "memory": 512,
      "essential": true,
      "environment": [
        {
          "name": "AWS_REGION",
          "value": "ap-southeast-2"
        },
        {
          "name": "AWS_CLOUDWATCH_NAMESPACE",
          "value": "gwilliams/confluentcloud"
        }
      ]
      "secrets": [
        {
          "name": "TF_VAR_DB_URL_SECRET",
          "valueFrom": "${aws_secretsmanager_secret.postgres.arn}:URL::"
        },
        {
          "name": "TF_VAR_CC_API_KEY",
          "valueFrom": "${aws_secretsmanager_secret.ccloud_metrics_api.arn}:CCLOUD_API_KEY::"
        },
        {
          "name": "TF_VAR_CC_API_SECRET",
          "valueFrom": "${aws_secretsmanager_secret.ccloud_metrics_api.arn}:CCLOUD_API_SECRET::"
        },
        {
          "name": "CCLOUD_METRICS_API_KEY",
          "valueFrom": "${aws_secretsmanager_secret.ccloud_metrics_api.arn}:CCLOUD_API_KEY::"
        },
        {
          "name": "CCLOUD_METRICS_API_SECRET",
          "valueFrom": "${aws_secretsmanager_secret.ccloud_metrics_api.arn}:CCLOUD_API_SECRET::"
        },        
      ],
      "command": [
        "--environment-id",
        "env-XXXXXX",
        "--kafka-cluster-id",
        "lkc-ZZZZZZ",
        "--config-ttl",
        "86400",
        "--daemon",
        "--verbose"
      ]
      "logConfiguration": { 
        "logDriver": "awslogs",
        "options": { 
          "awslogs-group" : aws_cloudwatch_log_group.ecs_task.name,
          "awslogs-region": "ap-southeast-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "telegraf_agent" {
  name            = "telegraf_agent_gwilliams"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.telegraf_agent.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    assign_public_ip = false
    subnets = [
      aws_subnet.private-a.id,
      aws_subnet.private-b.id,
    ]
  }
  security_groups = [aws_security_group.private-access.id]
}
