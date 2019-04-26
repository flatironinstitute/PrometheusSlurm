# PrometheusSlurm
This project is to use prometheus to monitor slurm jobs.

## Getting Started
Configuration
###Prometheus

Start and stop the services
```
docker-compose up -d
docker-compose stop 
```

The ports occupised by services are:
```
prom/prometheus:v2.8.0: 9090
grafana/grafana: 3000
docker_mqtt_exporter: 9344
```

The service interface are:
mon8:9090
