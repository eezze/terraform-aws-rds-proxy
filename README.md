# Terraform AWS RDS Aurora

## About:



### Resources deployed



## How to use:


```hcl
module "rds_proxy" {
  source  = "github.com/eezze/terraform-aws-rds-proxy"

  environment       = var.environment
  resource_tag_name = var.resource_tag_name

  db_instance_identifier = module.rds_instance.instance_id
  auth                   = local.auth
  vpc_security_group_ids = [module.vpc.vpc_default_security_group_id]
  vpc_subnet_ids         = module.vpc.public_subnet_ids

  debug_logging                = var.debug_logging
  engine_family                = var.engine_family
  idle_client_timeout          = var.idle_client_timeout
  require_tls                  = var.require_tls
  connection_borrow_timeout    = var.connection_borrow_timeout
  init_query                   = var.init_query
  max_connections_percent      = var.max_connections_percent
  max_idle_connections_percent = var.max_idle_connections_percent
  session_pinning_filters      = var.session_pinning_filters
  existing_iam_role_arn        = var.existing_iam_role_arn
}
```

## Changelog

### v1.0
 - Initial release