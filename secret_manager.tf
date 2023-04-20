resource "aws_secretsmanager_secret" "eks" {
  count                   = local.create && var.create_secretmanager_eks ? 1 : 0
  name                    = format("%s/eks/%s", var.master_prefix, var.cluster_name)
  recovery_window_in_days = var.recovery_window_in_days
  tags                    = var.tags
  provider                = aws.secret
  depends_on = [
    aws_eks_cluster.this,
  ]
}

resource "aws_secretsmanager_secret_version" "eks" {
  count     = local.create && var.create_secretmanager_eks ? 1 : 0
  secret_id = aws_secretsmanager_secret.eks[0].id
  secret_string = jsonencode({
    clusterName = aws_eks_cluster.this[0].id,
    caData      = aws_eks_cluster.this[0].certificate_authority[0].data,
    roleARN     = var.eks_deploy_role,
    server      = aws_eks_cluster.this[0].endpoint
  })
  provider = aws.secret
  depends_on = [
    aws_eks_cluster.this,
  ]
}
