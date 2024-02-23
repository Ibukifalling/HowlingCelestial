import os
from kubernetes import client, config


def detect_cluster_assets():
    config.load_incluster_config()

    # 创建 Kubernetes 客户端
    v1 = client.CoreV1Api()

    # 获取所有 Namespace
    namespaces = v1.list_namespace().items
    print("Namespaces:")
    for ns in namespaces:
        print("-", ns.metadata.name)

    # 获取所有 Pod
    pods = v1.list_pod_for_all_namespaces().items
    print("\nPods:")
    for pod in pods:
        print("- Namespace:", pod.metadata.namespace, ", Name:", pod.metadata.name)

    # 获取所有 Node
    nodes = v1.list_node().items
    print("\nNodes:")
    for node in nodes:
        print("- Name:", node.metadata.name, ", Status:", node.status)

