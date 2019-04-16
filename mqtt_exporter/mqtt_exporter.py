#!/usr/bin/env python

import prometheus_client as prometheus
from collections import defaultdict
import logging
import argparse
import json
import paho.mqtt.client as mqtt
import yaml
import os
import re
import operator
import time
from yamlreader import yaml_load
import sys

VERSION = '1.0'


def read_config(config_path):
    """Read config file from given location, and parse properties"""

    if config_path is not None:
        if os.path.isfile(config_path):
            logging.info('INFO: Config file found at: {0}'.format(config_path))
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f.read())
            except yaml.YAMLError:
                logging.exception('Failed to parse configuration file:')

        elif os.path.isdir(config_path):
            logging.info('INFO: Config directory found at: {0}'.format(config_path))
            try:
                return yaml_load(config_path)
            except yaml.YAMLError:
                logging.exception('Failed to parse configuration directory:')

    return {}


def parse_config_and_add_defaults(config_from_file):
    """Parse content of configfile and add default values where needed"""

    config = {}
    logging.debug('parse_config Config from file: {0}'.format(str(config_from_file)))
    # Logging values ('logging' is optional in config
    if 'logging' in config_from_file:
        config['logging'] = add_config_and_defaults(config_from_file['logging'], {'logfile': '', 'level': 'info'})
    else:
        config['logging'] = add_config_and_defaults(None, {'logfile': '', 'level': 'info'})

    # MQTT values
    if 'mqtt' in config_from_file:
        config['mqtt'] = add_config_and_defaults(config_from_file['mqtt'], {'host': 'localhost'})
    else:
        config['mqtt'] = add_config_and_defaults(None, {'host': 'localhost'})

    if 'auth' in config['mqtt']:
        config['mqtt']['auth'] = add_config_and_defaults(config['mqtt']['auth'], {})
        validate_required_labels(config['mqtt']['auth'], 'auth', ['username'])

    if 'tls' in config['mqtt']:
        config['mqtt']['tls'] = add_config_and_defaults(config['mqtt']['tls'], {})

    # Prometheus values
    if 'prometheus' in config:
        config['prometheus'] = add_config_and_defaults(config_from_file['prometheus'], {'exporter_port': 9344})
    else:
        config['prometheus'] = add_config_and_defaults(None, {'exporter_port': 9344})

    metrics = {}
    for metric in config_from_file['metrics']:
        parse_and_validate_metric_config(metric, metrics)

    config['metrics'] = group_by_topic(metrics.values())
    return config

def parse_and_validate_metric_config(metric, metrics):
    metrics[metric['name']] = metric


def validate_required_labels(config, parent, required_labels):
    """Fail if required_labels is not present in config"""
    for field in required_labels:
        if field not in config or config[field] is None:
            if parent is None:
                error = '\'{0}\' is a required field in configfile'.format(field)
            else:
                error = '\'{0}\' is a required parameter for field {1} in configfile'.format(field, parent)
            raise TypeError(error)


def add_config_and_defaults(config, defaults):
    """Return dict with values from config, if present, or values from defaults"""
    if config is not None:
        defaults.update(config)
    return defaults.copy()


def _strip_config(config, allowed_keys):
    return {k: v for k, v in config.items() if k in allowed_keys and v}


def group_by_topic(metrics):
    """Group metrics by topic"""
    t = defaultdict(list)
    for metric in metrics:
        t[metric['topic']].append(metric)
    return t

#topic1 may have wildcard
def topic_matches(topic1, topic2):
    """Check if wildcard-topics match"""
    if topic1 == topic2:
        return True

    # If topic1 != topic2 and no wildcard is present in topic1, no need for regex
    if '+' not in topic1 and '#' not in topic1:
        return False

    logging.debug('topic_matches: Topic1: {0}, Topic2: {1}'.format(topic1, topic2))
    topic1 = re.escape(topic1)
    regex = topic1.replace('\\/\\#', '.*$').replace('\\+', '[^/]+')  #convert topic1 into regex format
    match = re.match(regex, topic2)

    logging.debug('topic_matches: Match: {0}'.format(match is not None))
    return match is not None


# noinspection SpellCheckingInspection
def _log_setup(logging_config):
    """Setup application logging"""

    logfile = logging_config['logfile']

    log_level = logging_config['level']

    numeric_level = logging.getLevelName(log_level.upper())
    if not isinstance(numeric_level, int):
        raise TypeError('Invalid log level: {0}'.format(log_level))

    if logfile is not '':
        logging.info('Logging redirected to: ' + logfile)
        # Need to replace the current handler on the root logger:
        file_handler = logging.FileHandler(logfile, 'a')
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        file_handler.setFormatter(formatter)

        log = logging.getLogger()  # root logger
        for handler in log.handlers:  # remove all old handlers
            log.removeHandler(handler)
        log.addHandler(file_handler)

    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')

    logging.getLogger().setLevel(numeric_level)
    logging.info('log_level set to: {0}'.format(log_level))


# noinspection PyUnusedLocal
def on_connect(client, userdata, flags, rc):
    """The callback for when the client receives a CONNACK response from the server."""
    logging.info('Connected to broker, result code {0}'.format(str(rc)))

    for topic in userdata:
        client.subscribe(topic)
        logging.info('Subscribing to topic: {0}'.format(topic))

def get_dict_value (d, key_seq):
    for k in key_seq:
        d= d[k]

    return d

#return [label_names, label_values, values]
def retrieve_label_values (metric, msg):
    label_names = []
    label_values= []
    value_config = metric['value_config']
    value_raw    = get_dict_value(msg, value_config['source']) 
    for label_config in metric['label_configs']:
        label_name  = label_config['label_name']
        source      = get_dict_value(msg, label_config['source'])
        if label_config.get('source_type', '') =='dict':
           label_names.append (label_name)
           label_values.append(list(source.keys()))
           if value_config.get('label', '') == label_name:
              values = [float(v) for v in source.values()]
        else: #item
           label_names.append (label_config['label_name'])
           label_values.append(source)

    if value_config.get('type', '') == 'list':
       values     = [float(value_raw[value_config['index']])]
    elif value_config.get('type', '') == 'dict':
       values     = values
    else:
       values     = [float(value_raw)]
        
    return label_names, label_values, values     
    
def update_metrics(metrics, msg_payload):
    """For each metric on this topic, apply label renaming if present, and export to prometheus"""
    for metric in metrics:
        try:
           label_names, label_values, values = retrieve_label_values(metric, json.loads(msg_payload))
        except ValueError:
            logging.exception(
                'value must be a number {}:{}'.format(0, 0, label_names, label_values))
            continue

        logging.debug('update_metrics all labels:')
        if len(values) > 1:
           for idx in range(len(values)):
              label_v = []
              for l_v in label_values:
                  if ( type(l_v) == list ): 
                     label_v.append(l_v[idx])
                  else:
                     label_v.append(l_v)
              export_to_prometheus(metric['name'], metric, label_names, label_v, values[idx])
        else:
           export_to_prometheus(metric['name'], metric, label_names, label_values, values[0])


# noinspection PyUnusedLocal
def on_message(client, userdata, msg):
    """The callback for when a PUBLISH message is received from the server."""
    logging.debug('on_message Msg received on topic: {0}, Value: {1}'.format(msg.topic, str(msg.payload)))

    for topic in userdata:
        if topic_matches(topic, msg.topic):
            update_metrics(userdata[topic], msg.payload)


def mqtt_init(mqtt_config, metrics):
    """Setup mqtt connection"""
    mqtt_client = mqtt.Client(userdata=metrics)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message

    if 'auth' in mqtt_config:
        auth = _strip_config(mqtt_config['auth'], ['username', 'password'])
        mqtt_client.username_pw_set(**auth)

    if 'tls' in mqtt_config:
        tls_config = _strip_config(mqtt_config['tls'], ['ca_certs', 'certfile', 'keyfile', 'cert_reqs', 'tls_version'])
        mqtt_client.tls_set(**tls_config)

    mqtt_client.connect(**_strip_config(mqtt_config, ['host', 'port', 'keepalive']))
    return mqtt_client


def export_to_prometheus(name, metric, label_names, label_values, value):
    """Export metric and labels to prometheus."""
    valid_types = ['gauge', 'counter', 'summary', 'histogram']
    if metric['type'] not in valid_types:
        logging.warning(
            "Metric type: {0}, is not a valid metric type. Must be one of: {1}".format(metric['type'], valid_types))

    prometheus_metric_types = {'gauge': gauge,
                               'counter': counter,
                               'summary': summary,
                               'histogram': histogram}

    try:
        prometheus_metric_types[metric['type'].lower()](label_names, label_values, metric, name, value)
        logging.debug('export_to_prometheus metric {0}{1}{2} updated with value: {3}'.format(name, label_names, label_values, value))
    except KeyError:
        logging.warning(
            "Metric type: {0}, is not a valid metric type. Must be one of: {1}".format(metric['type'],
                                                                                       prometheus_metric_types.keys()))


def gauge(label_names, label_values, metric, name, value):
    """Define metric as Gauge, setting it to 'value'"""
    get_prometheus_metric(label_names, label_values, metric, name).set(value)


def get_prometheus_metric(label_names, label_values, metric, name, buckets=None):
    key = ':'.join([''.join(label_names), ''.join(label_values)])
    if 'prometheus_metric' not in metric or not metric['prometheus_metric']:
        metric['prometheus_metric'] = {}
        prometheus_metric_types = {'gauge': prometheus.Gauge,
                                   'counter': prometheus.Counter,
                                   'summary': prometheus.Summary,
                                   'histogram': prometheus.Histogram}

        metric_type = metric['type'].lower()
        if metric_type == 'histogram' and buckets:
            metric['prometheus_metric']['base'] = prometheus_metric_types[metric_type](name, metric['help'],
                                                                                       list(label_names), buckets)
        else:
            metric['prometheus_metric']['base'] = prometheus_metric_types[metric_type](name, metric['help'],
                                                                                       list(label_names))

    #newer value will overwriten old ones
    #if key not in metric['prometheus_metric'] or not metric['prometheus_metric'][key]:
    metric['prometheus_metric'][key] = metric['prometheus_metric']['base'].labels(*list(label_values))
    return metric['prometheus_metric'][key]


def counter(label_names, label_values, metric, name, value):
    """Define metric as Counter, increasing it by 'value'"""
    get_prometheus_metric(label_names, label_values, metric, name).inc(value)


def summary(label_names, label_values, metric, name, value):
    """Define metric as summary, observing 'value'"""
    get_prometheus_metric(label_names, label_values, metric, name).observe(value)


def histogram(label_names, label_values, metric, name, value):
    """Define metric as histogram, observing 'value'"""
    buckets = None
    if 'buckets' in metric and metric['buckets']:
        buckets = metric['buckets'].split(',')

    get_prometheus_metric(label_names, label_values, metric, name, buckets).observe(value)


def add_static_metric(timestamp):
    g = prometheus.Gauge('mqtt_exporter_timestamp', 'Startup time of exporter in millis since EPOC (static)',
                         ['exporter_version'])
    g.labels(VERSION).set(timestamp)


def _get_sorted_tuple_list(source):
    """Return a sorted list of tuples"""
    filtered_source = source.copy()
    sorted_tuple_list = sorted(filtered_source.items(), key=operator.itemgetter(0))
    return sorted_tuple_list

def main():
    add_static_metric(int(time.time() * 1000))
    # Setup argument parsing
    parser = argparse.ArgumentParser(description='Simple program to export formatted mqtt messages to prometheus')
    parser.add_argument('-c', '--config', action='store', dest='config', default='conf',
                        help='Set config location (file or directory), default: \'conf\'')
    options = parser.parse_args()

    # Initial logging to console
    _log_setup({'logfile': '', 'level': 'debug'})

    # Read config file from disk
    from_file = read_config(options.config)
    config    = parse_config_and_add_defaults(from_file)

    # Set up logging
    _log_setup(config['logging'])

    # Start prometheus exporter
    logging.info('Starting prometheus exporter on port: {0}'
                 .format(str(config['prometheus']['exporter_port'])))
    prometheus.start_http_server(config['prometheus']['exporter_port'])

    # Set up mqtt client and loop forever
    mqtt_client = mqtt_init(config['mqtt'], config['metrics'])
    mqtt_client.loop_forever()


if __name__ == '__main__':
    main()
