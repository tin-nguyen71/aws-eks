###############################################################################
#EKS CNI CUSTOM NETWORKING
###############################################################################

resource "aws_vpc_ipv4_cidr_block_association" "secondary_cidr" {
  count      = local.create && var.enable_cni_custom_network ? 1 : 0
  vpc_id     = var.vpc_id
  cidr_block = lookup(var.cni_custom_network, "vpc_ipv4_cidrs", "172.100.0.0/16")
}

resource "aws_subnet" "eks_subnet" {
  count             = local.create && var.enable_cni_custom_network ? length(data.aws_availability_zones.available.names) : 0
  vpc_id            = var.vpc_id
  cidr_block        = cidrsubnet(aws_vpc_ipv4_cidr_block_association.secondary_cidr[0].cidr_block, lookup(var.cni_custom_network, "number_subnet", "4"), count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = merge(
    var.tags,
    {
      Name = format("%s-%s-%s", var.master_prefix, lookup(var.cni_custom_network, "subnet_tag", "eks-subnet"), lower(data.aws_availability_zones.available.names[count.index]))
    }
  )
}

resource "null_resource" "label" {
  count = local.create && var.enable_cni_custom_network ? 1 : 0
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      aws eks --region ${data.aws_region.current.name} update-kubeconfig --name ${local.cluster_name}
      kubectl set env daemonset aws-node -n kube-system AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG=true && kubectl set env daemonset aws-node -n kube-system ENI_CONFIG_LABEL_DEF=topology.kubernetes.io/zone
    EOT
  }
  depends_on = [
    aws_eks_cluster.this,
  ]
}

resource "kubectl_manifest" "eni_config" {
  count = local.create && var.enable_cni_custom_network ? length(aws_subnet.eks_subnet) : 0
  yaml_body = templatefile("${path.module}/templates/eni_config.tpl", {
    name              = aws_subnet.eks_subnet[count.index].availability_zone
    security_group_id = local.node_security_group_id
    subnet_id         = aws_subnet.eks_subnet[count.index].id
  })
  depends_on = [
    module.fargate_profile,
    module.eks_managed_node_group,
    module.self_managed_node_group,
  ]
}
