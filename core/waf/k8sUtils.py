from kubernetes import client, config

# 加载 Kubernetes 配置
config.load_kube_config()

# 创建 Kubernetes 客户端实例
v1 = client.CoreV1Api()

# 存储服务名和端口的映射关系的字典
service_port_mapping = {}

# 获取所有服务列表
service_list = v1.list_service_for_all_namespaces().items

# 遍历服务列表并构建服务名和端口的映射关系
for service in service_list:
    if service.spec.type == 'NodePort':
        # 获取服务名
        service_name = service.metadata.name
        # 获取服务的第一个端口映射
        port_mapping = service.spec.ports[0]
        # 将服务名和端口的映射关系添加到字典中
        service_port_mapping[service_name] = port_mapping.node_port

# 打印服务名和端口的映射关系
for service_name, port in service_port_mapping.items():
    print(f"Service: {service_name}, Port: {port}")