db.createCollection("traffic_flows");

db.traffic_flows.createIndex(
  { timestamp: 1 },
  {
    expireAfterSeconds: 604800,  
    name: "ttl_7d_timestamp"
  }
);

db.traffic_flows.createIndex(
  { protocol: 1, timestamp: 1 },
  { name: "compound_protocol_timestamp" }
);

db.traffic_flows.createIndex(
  { src_ip: 1, timestamp: 1 },
  { name: "compound_src_ip_timestamp" }
);

db.createCollection("anomaly_events");

db.anomaly_events.createIndex(
  { rule_name: 1, src_ip: 1, dst_ip: 1, timestamp: 1 },
  {
    unique: true,
    name: "unique_anomaly_idempotency_key"
  }
);

db.anomaly_events.createIndex(
  { timestamp: -1 },
  { name: "idx_anomaly_timestamp_desc" }
);

db.createCollection("baseline_stats");

db.baseline_stats.createIndex(
  { src_ip: 1, dst_ip: 1, protocol: 1 },
  {
    unique: true,
    name: "unique_baseline_flow_key"
  }
);

print("init-collections.js complete — collections and indexes created.");