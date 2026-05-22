db = db.getSiblingDB(process.env.MONGO_DB || "telemetry");


db.createCollection("traffic_flows", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["src_ip", "dst_ip", "protocol", "timestamp", "flow_key"],
            properties: {
                src_ip:      { bsonType: "string" },
                dst_ip:      { bsonType: "string" },
                protocol:    {
                    bsonType: "string",
                    enum: ["TCP", "UDP", "ICMP", "ARP"]
                },
                timestamp:   { bsonType: "long" },  
                flow_key:    { bsonType: "string" },

                packet_size: { bsonType: ["int", "null"], minimum: 0, maximum: 65535 },
                direction:   { bsonType: ["string", "null"], enum: ["inbound", "outbound", null] },
                flags:       { bsonType: ["int", "null"] },
                src_port:    { bsonType: ["int", "null"], minimum: 0, maximum: 65535 },
                dst_port:    { bsonType: ["int", "null"], minimum: 0, maximum: 65535 },
                seq_num:     { bsonType: ["long", "null"] },
                ttl:         { bsonType: ["int", "null"] },
                src_mac:     { bsonType: ["string", "null"] },
                dst_mac:     { bsonType: ["string", "null"] },
                checksum_valid: { bsonType: ["bool", "null"] },
                is_retransmit:  { bsonType: ["bool", "null"] },

                first_seen:    { bsonType: ["long", "null"] },
                last_seen:     { bsonType: ["long", "null"] },
                total_bytes:   { bsonType: ["long", "null"] },
                inbound_bytes:  { bsonType: ["long", "null"] },
                outbound_bytes: { bsonType: ["long", "null"] },
                syn_count:     { bsonType: ["int", "null"] },
                syn_ack_count: { bsonType: ["int", "null"] },
                rst_count:     { bsonType: ["int", "null"] },

                arp_opcode:     { bsonType: ["int", "null"] },
                arp_sender_ip:  { bsonType: ["string", "null"] },
                arp_sender_mac: { bsonType: ["string", "null"] },
                arp_target_ip:  { bsonType: ["string", "null"] },

                icmp_type: { bsonType: ["int", "null"] },
                icmp_code: { bsonType: ["int", "null"] }
            }
        }
    },
    validationAction: "error",
    validationLevel:  "strict"
});

db.traffic_flows.createIndex(
    { timestamp: 1 },
    { expireAfterSeconds: 604800, name: "ttl_timestamp" }
);

db.traffic_flows.createIndex(
    { timestamp: 1, protocol: 1 },
    { name: "compound_timestamp_protocol" }
);

db.traffic_flows.createIndex(
    { timestamp: 1, src_ip: 1 },
    { name: "compound_timestamp_src_ip" }
);

db.traffic_flows.createIndex(
    { flow_key: 1, timestamp: 1 },
    { name: "idx_flow_key_timestamp" }
);

db.traffic_flows.createIndex(
    { src_ip: 1, dst_ip: 1, protocol: 1 },
    { name: "idx_ip_flow_lookup" }
);

print("traffic_flows: collection + indexes created");


db.createCollection("anomaly_events", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["rule_id", "flow_key", "src_ip", "detected_at", "source"],
            properties: {
                rule_id:     { bsonType: "int", minimum: 0, maximum: 15 },
                rule_name:   { bsonType: ["string", "null"] },
                flow_key:    { bsonType: "string" },
                src_ip:      { bsonType: "string" },
                dst_ip:      { bsonType: ["string", "null"] },
                evidence:    { bsonType: ["string", "null"] },
                severity:    {
                    bsonType: "string",
                    enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                },
                detected_at: { bsonType: "long" },   
                source:      {
                    bsonType: "string",
                    enum: ["threshold", "isolation_forest"]
                }
            }
        }
    },
    validationAction: "error",
    validationLevel:  "strict"
});

db.anomaly_events.createIndex(
    { detected_at: 1 },
    { expireAfterSeconds: 2592000, name: "ttl_detected_at" }
);

db.anomaly_events.createIndex(
    { flow_key: 1, rule_id: 1, detected_at: 1 },
    { unique: true, name: "unique_anomaly_per_flow_rule_time" }
);

db.anomaly_events.createIndex(
    { detected_at: 1, rule_id: 1 },
    { name: "compound_detected_at_rule_id" }
);

db.anomaly_events.createIndex(
    { src_ip: 1, detected_at: 1 },
    { name: "compound_src_ip_detected_at" }
);

db.anomaly_events.createIndex(
    { detected_at: -1 },
    { name: "idx_anomaly_timestamp_desc" }
);

print("anomaly_events: collection + indexes created");


db.createCollection("baseline_stats", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["flow_key", "window_start", "source"],
            properties: {
                flow_key:     { bsonType: "string" },
                protocol:     { bsonType: ["string", "null"] },
                window_start: { bsonType: "long" },   // ms since epoch
                source:       {
                    bsonType: "string",
                    enum: ["cicids2017", "live_traffic"]
                },
                mean:         { bsonType: ["double", "null"] },
                std_dev:      { bsonType: ["double", "null"] },
                sample_count: { bsonType: ["int", "null"] },
                percentile_buckets: { bsonType: ["object", "null"] }
            }
        }
    },
    validationAction: "error",
    validationLevel:  "strict"
});

db.baseline_stats.createIndex(
    { window_start: 1 },
    { expireAfterSeconds: 172800, name: "ttl_window_start" }
);

db.baseline_stats.createIndex(
    { flow_key: 1, window_start: 1 },
    { unique: true, name: "unique_flow_window" }
);

db.baseline_stats.createIndex(
    { flow_key: 1 },
    { name: "idx_baseline_flow_lookup" }
);

print("baseline_stats: collection + indexes created");
print("---");
print("MongoDB telemetry schema initialized successfully.");