#!/bin/bash

rev=$(git rev-parse HEAD)

sed -i -e "s/username/$1/g" -e "s/clock/$2/g" -e "s/81750055651bbe6db78ac1828abd43144f08213e/$rev/g" ~/csye7374/webapp-backend/k8s/backend-k8s-ReplicaSet.yaml

sed -i -e "s/username/$1/g" -e "s/clock/$2/g" -e "s/81750055651bbe6db78ac1828abd43144f08213e/$rev/g" ~/csye7374/webapp-backend/k8s/backend-k8s-job.yaml

cd

cd .docker/

base64=$(base64 config.json | tr -d \\n)

cd

cd ~/csye7374/webapp-backend/k8s

sed -i "s/secret/$base64/g" ~/csye7374/webapp-backend/k8s/backend-k8s-secrets.yaml

sed -i "s/RDS_URL/$3/g" backend-k8s-configMap.yaml
