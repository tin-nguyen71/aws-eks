locals {
  secret_assume_role = var.secret_assume_role == null || var.secret_assume_role == "" ? var.assume_role : var.secret_assume_role
}

provider "aws" {
  region = var.aws_region
  assume_role {
    role_arn = var.assume_role
  }
}

provider "aws" {
  region = var.aws_region
  alias  = "secret"

  assume_role {
    role_arn = local.secret_assume_role
  }
}
