#!/usr/bin/env python3
"""
Enumerate metrics service URLs for:
  * kafka clusters
  * schema registry
  * ksql
  * connectors

Environment variables
=====================
CONFLUENT_CLOUD_API_KEY
CONFLUENT_CLOUD_API_SECRET
"""
from psycopg.rows import dict_row
import requests
from requests_toolbelt.utils import dump
from requests.auth import HTTPBasicAuth
import psycopg
import logging
import argparse
from urllib.parse import urlparse
import sys
import os
from jinja2 import Environment

L = logging.getLogger(__name__)
METRICS_ENDPOINT = "https://api.telemetry.confluent.cloud/v2/metrics/cloud/export?"

CONFIG_TEMPLATE = """
###############################################################################
#                            Agent Setup                                      #
###############################################################################
[global_tags]

[agent]
  interval = "60s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  collection_jitter = "0s"
  flush_interval = "10s"
  flush_jitter = "0s"
  precision = "0s"
  hostname = ""
  omit_hostname = false

###############################################################################
#                            INPUT PLUGINS                                    #
###############################################################################

#
# Prometheus
# 
# https://github.com/influxdata/telegraf/blob/release-1.25/plugins/inputs/prometheus/README.md
[[inputs.prometheus]]

# Because of this issue we cannot supply array as environment variable so must programatically
# regenerate the config file and build a separate container for each environment:
# https://github.com/influxdata/telegraf/issues/5762
#
# Sample URLs (different for each type of component)
#   kafka cluster:      https://api.telemetry.confluent.cloud/v2/metrics/cloud/export?resource.kafka.id=lkc-ymmyqj
#   schema registry:    https://api.telemetry.confluent.cloud/v2/metrics/cloud/export?resource.schema_registry.id=lsrc-gqwk5r
#   ksql:               https://api.telemetry.confluent.cloud/v2/metrics/cloud/export?resource.ksql.id=lksqlc-ymqykp
#   connector:          https://api.telemetry.confluent.cloud/v2/metrics/cloud/export?resource.connector.id=lcc-8wd277&resource.kafka.id=lkc-9kg320&resource.ksql.id=lksqlc-7y3r02&resource.connector.id=lcc-8w6v2r&resource.schema.id=lsrc-x1gxg
urls = {{ metrics_urls | to_nice_json }}

metric_version = 1
username = "${CCLOUD_METRICS_API_KEY}"
password = "${CCLOUD_METRICS_API_SECRET}"

###############################################################################
#                            OUTPUT PLUGINS                                   #
###############################################################################

[[outputs.file]]
files = ["stdout"]


###############################################################################
#                      Examples/Other useful plugins                          #
###############################################################################

#
# Kafka
#
# https://github.com/influxdata/telegraf/blob/release-1.25/plugins/outputs/kafka/README.md
#

# Example of how to output to kafka topic

# [[outputs.kafka]]
# brokers = ["pkc-XXXXX.ap-southeast-1.aws.confluent.cloud:9092"]
# topic = "telegraf_metrics"
# client_id = "Telegraf"
# version = "3.0.0"
# enable_tls = true
# sasl_username = "${CCLOUD_API_KEY}"
# sasl_password = "${CCLOUD_API_SECRET}"
# sasl_mechanism = "PLAIN"
# data_format = "json"


#
# OpenTelemetry
#
# https://github.com/influxdata/telegraf/blob/release-1.25/plugins/outputs/opentelemetry/README.md

#
# SumoLogic
#
# https://github.com/influxdata/telegraf/blob/release-1.25/plugins/outputs/sumologic/README.md
"""


def http_cc_get_json(url, verbose):
    http = requests.Session()
    if verbose:
        http.hooks["response"] = [logging_hook]
    
    response = http.get(
        url,
        auth=HTTPBasicAuth(os.environ['TF_VAR_CC_API_KEY'],os.environ['TF_VAR_CC_API_SECRET']),
    )

    return response.json()


def get_postgres_connection(url):
    # Extract URL parameters to individual fields as required by psycopg
    # https://stackoverflow.com/a/70955998/3441106
    p = urlparse(url)
    pg_connection_dict = {
        'user': p.username,
        'password': p.password,
        'host': p.hostname,
        'port': p.port,
        'dbname': p.path[1:],
    }
    L.debug(f"Parsed connection to: {pg_connection_dict}")
    return psycopg.connect(**pg_connection_dict, row_factory=dict_row)


def get_connector_names_from_postgres(url):
    with get_postgres_connection(url) as conn:
        sql = "SELECT key FROM confluent_cloud_connectors WHERE managed = true"
        curr = conn.execute(sql)
        data = curr.fetchall()
        L.debug(f"found {len(data)} connectors")

        return data

# requests logging - https://stackoverflow.com/a/70156057/3441106
def logging_hook(response, *args, **kwargs):
    data = dump.dump_all(response)
    print(data.decode('utf-8'))


def get_connector_metrics_urls(environment_id, kafka_cluster_id, verbose):
    """Get the metrics URL for every connector the database knows about in this cluster"""


    # database is the point-of-truth so get the connector names from there... (list of connector names)
    connector_names = [r["key"] for r in get_connector_names_from_postgres(os.environ['TF_VAR_DB_URL_SECRET'])]

    # ask CC for all the connectors in the environment (this is the only way to get the connector ID) 
    # (dict of connector name -> info)
    cc_connector_info = http_cc_get_json(
        f"https://api.confluent.cloud/connect/v1/environments/{environment_id}/clusters/{kafka_cluster_id}/connectors?expand=id",
        verbose
    )

    # munge the two lists together to get a connector metrics URL, we always generate a metrics URL for every
    # connector found in the database so that we can see that the connector is missing
    connector_urls = []
    for connector_name in connector_names:
        connector_id = cc_connector_info.get(connector_name, {}).get('id', {}).get('id', 'CONNECTOR_NOT_DEFINED_IN_CONFLUENT_CLOUD')
        connector_urls.append(f"{METRICS_ENDPOINT}resource.connector.id={connector_id}")

    return connector_urls

def extract_id_from_metadata(cluster_info, kafka_cluster_id):
    """
    1:  The `.data.id` field in starts `dlz-` but we must extract the id starting `lksqlc-` which is in 
        the `.data.metadata.self`.
    2:  Filter the ksql clusters to only match a kafka cluster
    
    Return the KSQL cluster id or False if it should be ignored
    """

    # extract ksql cluster ID
    self_url = cluster_info.get("metadata", {}).get("self", "")
    p = urlparse(self_url)
    # item after the last `/` is the cluster id
    id = p.path.split('/')[-1]
    
    # filter the kafka cluster id if requested
    if kafka_cluster_id:
        ksql_kafka_cluster = cluster_info.get("spec", {}).get("kafka_cluster", {}).get("id", False)
        if ksql_kafka_cluster == kafka_cluster_id:
            result = id
        else:
            L.debug(f"skipped ksql cluster: {id} - {ksql_kafka_cluster} is not part of kafka cluster: {kafka_cluster_id}")
            result = False
    else:
        result = id
    return result


def get_ksql_metrics_urls(environment_id, kafka_cluster_id, verbose):
    """Get the KSQL clusters - these come from a paginated API call that gives the clusters for the whole environment,
    this then needs to be filtered per-cluster"""
    ksql_metrics_urls = []

    # first page
    response_json = http_cc_get_json(
        f"https://api.confluent.cloud/ksqldbcm/v2/clusters?environment={environment_id}",\
        verbose
    )
    response_json_data = response_json.get("data", False)
    if response_json_data:
        # `data` will be None if no ksql clusters are defined
        for cluster_info in response_json_data:
            # filter only the kafka cluster we are looking at
            ksql_cluster_id = extract_id_from_metadata(cluster_info, kafka_cluster_id)
            if ksql_cluster_id:
                ksql_metrics_urls.append(f"{METRICS_ENDPOINT}resource.ksql.id={ksql_cluster_id}")

        # subsequent pages
        while response_json.get("metadata", {}).get("next", False):
            # this is not tested due to needing 100+ clusters to trigger paging...
            L.debug("paged next page of KSQL clusters")

            # overwrite previous result
            response_json = http_cc_get_json(response_json.get("metadata").get("next"))
            response_json_data = response_json.get("data")
            if response_json_data:
                for cluster_info in response_json_data:
                    ksql_cluster_id = extract_id_from_metadata(cluster_info, kafka_cluster_id)
                    if ksql_cluster_id:
                        ksql_metrics_urls.append(f"{METRICS_ENDPOINT}resource.ksql.id={ksql_cluster_id}")

    return ksql_metrics_urls

def get_schema_registry_metrics_urls(environment_id, _, verbose):
    """schema registries are added 1:1 with environments so cluster filtering not applicable"""
    response_json = http_cc_get_json(
        f"https://api.confluent.cloud/srcm/v2/clusters?environment={environment_id}",
        verbose
    )

    # `data` should be a list of 0 or 1 entries describing schema registry clusters (0 if you have not
    # enabled for this environment)
    sr_clusters = response_json.get("data", [])
    if len(sr_clusters):
        sr_cluster_id = extract_id_from_metadata(sr_clusters[0], False)
        result = [f"{METRICS_ENDPOINT}resource.schema_registry.id={sr_cluster_id}"]
    else:
        result = []

    return result    

def get_cc_connector_ids_from_name(environment_id, kafka_cluster_id, connector_name, verbose):
    http = requests.Session()
    if verbose:
        http.hooks["response"] = [logging_hook]
    
    response = http.get(
        f"https://api.confluent.cloud/connect/v1/environments/{environment_id}/clusters/{kafka_cluster_id}/connectors/{connector_name}",
        auth=HTTPBasicAuth(os.environ['TF_VAR_CC_API_KEY'],os.environ['TF_VAR_CC_API_SECRET']),
    )

    json_response = response.json()
    if response.status_code == 404:
        # no such connector
        L.debug(json_response)
        L.error("no such connector!")
    else:
        print(json_response)


def render_template(environment_id, kafka_cluster_id, verbose):
    jinja2Env = Environment(extensions=['jinja2_ansible_filters.AnsibleCoreFiltersExtension'])
    template = jinja2Env.from_string(CONFIG_TEMPLATE)
    metrics_urls = [
        # kafka cluster
        *[f"{METRICS_ENDPOINT}resource.kafka.id={kafka_cluster_id}"],

        # ksql
        *get_ksql_metrics_urls(environment_id, kafka_cluster_id, verbose),

        # schema registry
        *get_schema_registry_metrics_urls(environment_id, kafka_cluster_id, verbose),

        # connectors
        *get_connector_metrics_urls(environment_id, kafka_cluster_id, verbose)
    ]
    print(template.render(metrics_urls=metrics_urls))



def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--environment-id', dest='environment_id', help="Environment ID to get limits from, eg env-xg59z")
    parser.add_argument('--kafka-cluster-id', dest='kafka_cluster_id', help="Cluster ID to get limits from, eg lkc-w9ykm")
    parser.add_argument('--verbose', dest='verbose', default=False, action='store_true', help="Print debug info")
    parser.add_argument('--test-postgres', dest='test_postgres', default=False, action='store_true', help="Test connection to Postgres, then exit")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stdout)
    L.debug(args)

    if args.test_postgres:
        with get_postgres_connection(os.environ['TF_VAR_DB_URL_SECRET']) as conn:
            if len(conn.execute("SELECT 1").fetchall()):
                print("OK")
    else:
        if not args.environment_id:
            print ("must supply --environment-id")
            sys.exit(1)
        if not args.kafka_cluster_id:
            print ("must supply --kafka-cluster-id")
            sys.exit(1)
        
        render_template(args.environment_id, args.kafka_cluster_id, args.verbose)

    
if __name__ == "__main__":
    main()
