#!/bin/bash

kubectl delete -f deployment/adminuser.yaml
kubectl delete -f deployment/howling.yaml
echo 'removed'