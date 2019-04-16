docker run --name prometheus -d -p 9090:9090 prom/prometheus
docker run -d -p 3000:3000 grafana/grafana

Custom image
To avoid managing a file on the host and bind-mount it, the configuration can be baked into the image. This works well if the configuration itself is rather static and the same across all environments.

For this, create a new directory with a Prometheus configuration and a Dockerfile like this:

FROM prom/prometheus
ADD prometheus.yml /etc/prometheus/
Now build and run it:

docker build -t my-prometheus .
docker run -p 9090:9090 my-prometheus

Volumes & bind-mount
Bind-mount your prometheus.yml from the host by running:

docker run -p 9090:9090 -v /tmp/prometheus.yml:/etc/prometheus/prometheus.yml \
       prom/prometheus
Or use an additional volume for the config:

docker run -p 9090:9090 -v /prometheus-data \
       prom/prometheus --config.file=/prometheus-data/prometheus.yml


promethus: 9090
gafana: 3030
mqtt: 9344

#build image and move around
cd projects/prometheus/mqtt_exporter
docker build -t mqtt_exporter . 
docker run -p 9344:9344 mqtt_exporter
docker run --network host mqtt_exporter

docker image save -o mqtt_exporter.tar mqtt_exporter
#docker save --output mqtt_exporter.tar mqtt_exporter
docker-compose up -d
docker-compose stop 

docker inspect image_name

#one-time
systemctl enable docker
usermod -a -G docker yliu #re-log to take effect

lsof -i -P -n | grep LISTEN
docker inspect -f '{{.State.Pid}}' 0e15febc32e6
nsenter -t 2412888 -n netstat -pan
tcpdump -i p1p2 port 41228
lsof | grep scclin011

iptables -t nat -A DOCKER -p tcp --dport 9300 -j DNAT --to-destination 172.17.0.3:9300
iptables -t nat -A DOCKER -p tcp -s 10.128.36.18 -j DNAT -d 172.17.0.2

docker run --network host mqtt_exporter
scclin011
tcp        0      0 10.128.45.55:34001      10.128.36.18:1883       ESTABLISHED 3078044/python
mon5
mosquitto   2772        mosquitto  501u     IPv4           16185069       0t0        TCP mon5.flatironinstitute.org:ibm-mqisdp->scclin011.flatironinstitute.org:34001 (ESTABLISHED)

docker run -p 9344:9344 mqtt_exporter
scclin011
tcp        0      0 172.17.0.2:54895        10.128.36.18:1883       ESTABLISHED 3081362/python 
mon5
mosquitto   2772        mosquitto  391u     IPv4           16194084       0t0        TCP mon5.flatironinstitute.org:ibm-mqisdp->scclin011.flatironinstitute.org:54895 (ESTABLISHED)


docker cp db0dce3598a6:/tmp/mqtt_exporter.log mqtt_exporter.log
# PrometheusSlurm
