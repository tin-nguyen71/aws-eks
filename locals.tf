locals {
  create          = var.create_eks
  cluster_name    = format("%s-%s", var.master_prefix, var.cluster_name)
  cluster_sg_name = format("%s-cluster", local.cluster_name)
  node_sg_name    = format("%s-node", local.cluster_name)
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  # Cluster Security Group

  cluster_security_group_id = aws_security_group.cluster[0].id

  cluster_security_group_rules = {
    ingress_nodes_443 = {
      description                = "Node groups to cluster API"
      protocol                   = "tcp"
      from_port                  = 443
      to_port                    = 443
      type                       = "ingress"
      source_node_security_group = true
    }
    egress_nodes_443 = {
      description                = "Cluster API to node groups"
      protocol                   = "tcp"
      from_port                  = 443
      to_port                    = 443
      type                       = "egress"
      source_node_security_group = true
    }
    egress_nodes_kubelet = {
      description                = "Cluster API to node kubelets"
      protocol                   = "tcp"
      from_port                  = 10250
      to_port                    = 10250
      type                       = "egress"
      source_node_security_group = true
    }
  }

  # Node Security Group

  node_security_group_id = aws_security_group.node[0].id

  node_security_group_rules = {
    egress_cluster_443 = {
      description                   = "Node groups to cluster API"
      protocol                      = "tcp"
      from_port                     = 443
      to_port                       = 443
      type                          = "egress"
      source_cluster_security_group = true
    }
    ingress_cluster_443 = {
      description                   = "Cluster API to node groups"
      protocol                      = "tcp"
      from_port                     = 443
      to_port                       = 443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    ingress_cluster_kubelet = {
      description                   = "Cluster API to node kubelets"
      protocol                      = "tcp"
      from_port                     = 10250
      to_port                       = 10250
      type                          = "ingress"
      source_cluster_security_group = true
    }
    ingress_self_coredns_tcp = {
      description = "Node to node CoreDNS"
      protocol    = "tcp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      self        = true
    }
    egress_self_coredns_tcp = {
      description = "Node to node CoreDNS"
      protocol    = "tcp"
      from_port   = 53
      to_port     = 53
      type        = "egress"
      self        = true
    }
    ingress_self_coredns_udp = {
      description = "Node to node CoreDNS"
      protocol    = "udp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      self        = true
    }
    egress_self_coredns_udp = {
      description = "Node to node CoreDNS"
      protocol    = "udp"
      from_port   = 53
      to_port     = 53
      type        = "egress"
      self        = true
    }
    egress_https = {
      description      = "Egress all HTTPS to internet"
      protocol         = "tcp"
      from_port        = 443
      to_port          = 443
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = var.cluster_ip_family == "ipv6" ? ["::/0"] : null
    }
    egress_ntp_tcp = {
      description      = "Egress NTP/TCP to internet"
      protocol         = "tcp"
      from_port        = 123
      to_port          = 123
      type             = "egress"
      cidr_blocks      = var.node_security_group_ntp_ipv4_cidr_block
      ipv6_cidr_blocks = var.cluster_ip_family == "ipv6" ? var.node_security_group_ntp_ipv6_cidr_block : null
    }
    egress_ntp_udp = {
      description      = "Egress NTP/UDP to internet"
      protocol         = "udp"
      from_port        = 123
      to_port          = 123
      type             = "egress"
      cidr_blocks      = var.node_security_group_ntp_ipv4_cidr_block
      ipv6_cidr_blocks = var.cluster_ip_family == "ipv6" ? var.node_security_group_ntp_ipv6_cidr_block : null
    }
  }
  # IAM Role
  create_iam_role                = local.create && var.create_iam_role
  iam_role_name                  = coalesce(var.iam_role_name, "${local.cluster_name}-cluster-role")
  policy_arn_prefix              = "arn:${data.aws_partition.current.partition}:iam::aws:policy"
  cluster_encryption_policy_name = coalesce(var.cluster_encryption_policy_name, "${local.cluster_name}-cluster-encryption-role")
  dns_suffix                     = coalesce(var.cluster_iam_role_dns_suffix, data.aws_partition.current.dns_suffix)
  subnet_ids                     = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.selected.ids
  cluster_role                   = try(aws_iam_role.cluster_role[0].arn, var.iam_role_arn)
}
