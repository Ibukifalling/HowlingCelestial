#!/bin/bash

# Checking kubectl setup
kubectl version > /dev/null 2>&1 
if [ $? -eq 0 ];
then
    echo "kubectl setup looks good."
else 
    echo "Error: Could not find kubectl or an other error happened, please check kubectl setup."
    exit;
fi

kubectl apply -f deployment/adminuser.yaml
kubectl apply -f deployment/howling.yaml

TIMEOUT=300  # 设置超时时间为300秒
INTERVAL=10  # 设置轮询间隔为10秒

echo 'Waiting for the pod to be ready...'
kubectl wait --for=condition=Ready pod/howling-celestial

kubectl cp ./core howling-celestial:/howling-celestial

kubectl exec howling-celestial -- pip install kubernetes click

echo 'Successfully deployed Howling-Celestial.'
echo ''