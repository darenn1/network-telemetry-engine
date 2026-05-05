set -euo pipefail

RABBITMQ_USER=${RABBITMQ_USER:-guest}
RABBITMQ_PASS=${RABBITMQ_PASS:-guest}
RABBITMQ_HOST=${RABBITMQ_HOST:-localhost}
RABBITMQ_API="http://${RABBITMQ_HOST}:15672/api"

echo "[reset.sh] Purging RabbitMQ queues..."

purge_queue() {
    local queue=$1
    echo "[reset.sh]   purging queue: ${queue}"

    curl -s -o /dev/null -w "%{http_code}" \
        -u "${RABBITMQ_USER}:${RABBITMQ_PASS}" \
        -X DELETE \
        "${RABBITMQ_API}/queues/%2F/${queue}/contents" | \
        grep -q "204" && \
        echo "[reset.sh]   ${queue} purged" || \
        echo "[reset.sh]   ${queue} not found or already empty"
}

purge_queue "raw_packets.spring"
purge_queue "raw_packets.failed"

echo "[reset.sh] Done"