#!/bin/bash

read -p "Enter Your Username: "  username

read -p "Enter Your Image Name: "  image

rev=$(git rev-parse HEAD)

sed -i -e "s/username/$username/g" -e "s/image/$image/g" -e "s/81750055651bbe6db78ac1828abd43144f08213e/$rev/g" backend-k8s-ReplicaSet.yaml

sed -i -e "s/username/$username/g" -e "s/image/$image/g" -e "s/81750055651bbe6db78ac1828abd43144f08213e/$rev/g" backend-k8s-job.yaml

cd

cd .docker/

base64=$(base64 config.json | tr -d \\n)

cd

cd ./csye7374/webapp-backend/k8s
sed -i "s/secret/$base64/g" backend-k8s-secrets.yaml

read -p "Enter Your RDS_URL: "  RDS_URL

sed -i "s/RDS_URL/$RDS_URL/g" backend-k8s-configMap.yaml
