apiVersion: crd.k8s.amazonaws.com/v1alpha1
kind: ENIConfig
metadata: 
  name: ${name}
spec: 
  securityGroups: 
    - ${security_group_id}
  subnet: ${subnet_id}
