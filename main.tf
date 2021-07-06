locals {
  resource_name_prefix = "${var.environment}-${var.resource_tag_name}"
  name ="${local.resource_name_prefix}-rds-proxy"

  asm_secret_arns  = compact([for auth in var.auth : lookup(auth, "secret_arn", "")])
  kms_key_arn      = join("", data.aws_kms_key._.*.arn)
}

data "aws_region" "_" {
}

#-------------------------------------------------------------------------------
# AWS IAM
#-------------------------------------------------------------------------------

# Get information about the KMS Key used to encrypt secrets in AWS Secrets Manager
# If `kms_key_id` is not provided, use the AWS account's default CMK (the one named `aws/secretsmanager`)
data "aws_kms_key" "_" {
  count  = var.proxy_enabled ? 1 : 0
  key_id = var.kms_key_id != null && var.kms_key_id != "" ? var.kms_key_id : "alias/aws/secretsmanager"
}

data "aws_iam_policy_document" "assume_role" {
  count = var.proxy_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "_" {
  count = var.proxy_enabled ? 1 : 0

  statement {
    sid = "AllowRdsToGetSecretValueFromSecretsManager"

    actions = [
      "secretsmanager:GetSecretValue"
    ]

    resources = local.asm_secret_arns
  }

  statement {
    sid = "AllowRdsToUseKmsKeyToDecryptSecretValuesInSecretsManager"

    actions = [
      "kms:Decrypt"
    ]

    resources = [
      local.kms_key_arn
    ]

    condition {
      test     = "StringEquals"
      values   = [format("secretsmanager.%s.amazonaws.com", join("", data.aws_region._.*.name))]
      variable = "kms:ViaService"
    }
  }
}

resource "aws_iam_policy" "_" {
  count  = var.proxy_enabled ? 1 : 0
  name   = "${local.name}-iam-policy"
  policy = join("", data.aws_iam_policy_document._.*.json)
}

resource "aws_iam_role" "_" {
  count              = var.proxy_enabled ? 1 : 0
  name               = "${local.name}-iam-role"
  assume_role_policy = join("", data.aws_iam_policy_document.assume_role.*.json)
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "_" {
  count      = var.proxy_enabled ? 1 : 0
  policy_arn = join("", aws_iam_policy._.*.arn)
  role       = join("", aws_iam_role._.*.name)
}

#-------------------------------------------------------------------------------
# AWS RDS DB Proxy
#-------------------------------------------------------------------------------

resource "aws_db_proxy" "_" {
  count              = var.proxy_enabled ? 1 : 0

  name                   = local.name
  debug_logging          = var.debug_logging
  engine_family          = var.engine_family
  idle_client_timeout    = var.idle_client_timeout
  require_tls            = var.require_tls
  role_arn               = try(join("", aws_iam_role._.*.arn), "")
  vpc_security_group_ids = var.vpc_security_group_ids
  vpc_subnet_ids         = var.vpc_subnet_ids

  dynamic "auth" {
    for_each = var.auth

    content {
      auth_scheme = auth.value.auth_scheme
      description = auth.value.description
      iam_auth    = auth.value.iam_auth
      secret_arn  = auth.value.secret_arn
    }
  }

  tags = var.tags
}

resource "aws_db_proxy_default_target_group" "_" {
  count = var.proxy_enabled ? 1 : 0

  db_proxy_name = one(aws_db_proxy._.*.name)

  dynamic "connection_pool_config" {
    for_each = (
      var.connection_borrow_timeout != null || var.init_query != null || var.max_connections_percent != null ||
      var.max_idle_connections_percent != null || var.session_pinning_filters != null
    ) ? ["true"] : []

    content {
      connection_borrow_timeout    = var.connection_borrow_timeout
      init_query                   = var.init_query
      max_connections_percent      = var.max_connections_percent
      max_idle_connections_percent = var.max_idle_connections_percent
      session_pinning_filters      = var.session_pinning_filters
    }
  }
}

resource "aws_db_proxy_target" "_" {
  count = var.proxy_enabled ? 1 : 0

  db_instance_identifier = var.db_instance_identifier
  db_cluster_identifier  = var.db_cluster_identifier
  db_proxy_name          = one(aws_db_proxy._.*.name)
  target_group_name      = one(aws_db_proxy_default_target_group._.*.name)
}