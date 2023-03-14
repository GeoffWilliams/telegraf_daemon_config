export TF_VAR_CC_API_KEY=$CONFLUENT_CLOUD_API_KEY
export TF_VAR_CC_API_SECRET=$CONFLUENT_CLOUD_API_SECRET
export TF_VAR_DB_URL_SECRET=postgresql://terraform_cloud_confluent:keil6TodakotaDeighie@192.168.4.7:5432/postgres


/app/telegraf_daemon_config.py --environment-id env-w5502w --kafka-cluster-id lkc-7n1ny1

docker build . -t telegrafx --network host


docker run  -e TF_VAR_CC_API_KEY=$CONFLUENT_CLOUD_API_KEY \
            -e TF_VAR_CC_API_SECRET=$CONFLUENT_CLOUD_API_SECRET \
            -e CCLOUD_METRICS_API_KEY=$CONFLUENT_CLOUD_API_KEY \
            -e CCLOUD_METRICS_API_SECRET=$CONFLUENT_CLOUD_API_SECRET \
            -e TF_VAR_DB_URL_SECRET=postgresql://terraform_cloud_confluent:keil6TodakotaDeighie@192.168.4.7:5432/postgres \
            -ti telegrafx --environment-id env-w5502w --kafka-cluster-id lkc-7n1ny1

# moneshot
docker run  -e TF_VAR_CC_API_KEY=$CONFLUENT_CLOUD_API_KEY \
            -e TF_VAR_CC_API_SECRET=$CONFLUENT_CLOUD_API_SECRET \
            -e CCLOUD_METRICS_API_KEY=$CONFLUENT_CLOUD_API_KEY \
            -e CCLOUD_METRICS_API_SECRET=$CONFLUENT_CLOUD_API_SECRET \
            -e TF_VAR_DB_URL_SECRET=postgresql://terraform_cloud_confluent:keil6TodakotaDeighie@192.168.4.7:5432/postgres \
            -ti telegrafx --environment-id env-w5502w --kafka-cluster-id lkc-7n1ny1 --daemon


