# telegraf daemon config

## Features

* read connectors defined in database, correlate this list with the connectors defined in Confluent Cloud API
* query Confluent Cloud API for list of KSQL clusters and schema registries
* reload configuration in `--daemon` mode, `--config-ttl` sets time to rebuild config file after
* main script contains the config file template for ease of editing
* rebuilt config file is output on reload

## Quickstart (dynamic)

1. Clone this repository locally
2. Create ECR repository in AWS
3. In the repository click `View push commands`
    1. create the file `.env` and add a line like this (adapted from step 4 to replace version `latest` with a named release): 

    ```
    ECR_TAG=xxxx.dkr.ecr.ap-southeast-2.amazonaws.com/theimagename:0.1.0
    ```
    2. Login your `docker` cli to AWS (follow step 1 in dialog)
4. build the _dynamic_ image:

```
make
```

5. Edit and run [examples/terraform.tf](examples/terraform.tf) to define cloudwatch log group (for container logs) ECS cluster, service and task definition. Secrets defined are for example (and you wouldn't want your secrets in git) - make the corresponding secrets via clickops and reference the ARNs in the task definition

## Quickstart (static)

As a fallback, you can dump config file locally and include it in a static image:

```
# collect pips into a venv
python -m venv env
. env/bin/activate
pip install -r requirements.txt

export TF_VAR_CC_API_KEY=$CONFLUENT_CLOUD_API_KEY
export TF_VAR_CC_API_SECRET=$CONFLUENT_CLOUD_API_SECRET
export TF_VAR_DB_URL_SECRET=postgresql://terraform_cloud_confluent:xxx@192.168.4.7:5432/postgres
./telegraf_daemon_config.py --environment-id env-xxxxxx --kafka-cluster-id lkc-zzzzzz > telegraf.conf
make static
```

> **Warning**
> This replaces any current dynamic image!


## Troubleshooting

* Add `--verbose` to the task definition JSON `command`, this will print out a lot of debugging informations
* Make sure all required environment variables are set, see top of script for details
* If looking at ECS container logs, wait a few minutes for containers to start and load - they can be slow
* Too many restarts? check the value of `--config-ttl`
* Container dying? Probably can't build the initial config file - check the container logs for the _previous_ task
* Changes in DB not showing up? Maybe a bad reload and we're using the last config or maybe `--config-ttl` too long - check the container logs

