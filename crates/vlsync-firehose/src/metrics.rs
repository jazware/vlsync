//! The firehose's and backfill's Prometheus series.

use prometheus::{
    exponential_buckets, register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use vlsync_store::lazy;
use vlsync_store::metrics::latency_buckets;

lazy!(FIREHOSE_EVENTS: IntCounter = register_int_counter!("vlpds_firehose_events_total", "Events emitted by the merger"));
lazy!(FIREHOSE_BATCH: Histogram = register_histogram!("vlpds_firehose_merge_batch_events", "Events per merged batch", exponential_buckets(1.0, 2.0, 16).unwrap()));
lazy!(FIREHOSE_SUBSCRIBERS: IntGauge = register_int_gauge!("vlpds_firehose_subscribers", "Connected subscribeRepos clients"));
lazy!(FIREHOSE_RING_BYTES: IntGauge = register_int_gauge!("vlpds_firehose_ring_bytes", "Bytes held in the in-memory firehose ring"));
lazy!(FIREHOSE_DISCONNECTS: IntCounterVec = register_int_counter_vec!("vlpds_firehose_disconnects_total", "Subscriber disconnects by reason", &["reason"]));
lazy!(FIREHOSE_SENT: IntCounter = register_int_counter!("vlpds_firehose_frames_sent_total", "Frames sent to subscribers"));
lazy!(FIREHOSE_MERGE_QUEUE_BYTES: IntGauge = register_int_gauge!("vlpds_firehose_merge_queue_bytes", "Frame bytes queued in the merger waiting for the min watermark"));
lazy!(FIREHOSE_MERGE_QUEUE_BUDGET: IntGauge = register_int_gauge!("vlpds_firehose_merge_queue_budget_bytes", "Configured byte budget of the merger's queues (--firehose-merge-queue-mb); past it a log spills to S3 read-back"));
lazy!(FIREHOSE_MAX_LAG: IntGauge = register_int_gauge!("vlpds_firehose_max_lag_bytes", "Configured subscriber lag past which a live subscriber is cut off with ConsumerTooSlow (--firehose-max-lag-mb)"));
lazy!(FIREHOSE_SPILLS: IntCounter = register_int_counter!("vlpds_firehose_merge_spills_total", "Logs the merger stopped queueing (over budget) and reads back from S3"));
lazy!(FIREHOSE_SPILL_SEGMENTS: IntCounter = register_int_counter!("vlpds_firehose_merge_spill_segments_total", "Segments the merger read back from S3 for spilled logs"));
lazy!(FIREHOSE_SENT_BYTES: IntCounter = register_int_counter!("vlpds_firehose_bytes_sent_total", "Websocket bytes written to subscribers (frames + headers)"));
lazy!(FIREHOSE_BACKFILL_GETS: IntCounter = register_int_counter!("vlpds_firehose_backfill_gets_total", "Segment GETs made by cursor backfill readers"));
lazy!(FIREHOSE_BACKFILL_CACHE: IntCounterVec = register_int_counter_vec!("vlpds_firehose_backfill_cache_total", "Backfill segment cache lookups (hit includes joining a GET in flight)", &["result"]));
lazy!(FIREHOSE_BACKFILL_EVENTS: IntCounter = register_int_counter!("vlpds_firehose_backfill_events_total", "Events sent to subscribers from S3 backfill"));
lazy!(FIREHOSE_BACKFILLS: IntGaugeVec = register_int_gauge_vec!("vlpds_firehose_backfills", "Cursor backfills running, and waiting for a slot (--firehose-max-backfills)", &["state"]));
lazy!(FIREHOSE_CONNECTIONS: IntCounterVec = register_int_counter_vec!("vlpds_firehose_connections_total", "subscribeRepos connections upgraded, by mode (live: no cursor; backfill: with a cursor, replayed from the ring or the bucket)", &["mode"]));
lazy!(FIREHOSE_SUBSCRIBER_EVENTS: IntCounterVec = register_int_counter_vec!("vlpds_firehose_subscriber_events_total", "Events sent to each subscribeRepos connection: ip (client address, IPv6 /64), conn (node-local connection id, as the console lists it), relay (the configured relay it matched, or empty). Removed when the connection closes; past 1,000 connections on a node the rest share ip=\"other\", conn=\"other\"", &["ip", "conn", "relay"]));
lazy!(FIREHOSE_SUBSCRIBER_BYTES: IntCounterVec = register_int_counter_vec!("vlpds_firehose_subscriber_bytes_total", "Websocket bytes sent to each subscribeRepos connection, labelled as vlpds_firehose_subscriber_events_total", &["ip", "conn", "relay"]));
lazy!(FIREHOSE_REJECTED: IntCounterVec = register_int_counter_vec!("vlpds_firehose_rejected_total", "subscribeRepos connections refused before the upgrade, by reason (per_ip: --firehose-max-per-ip)", &["reason"]));
lazy!(FIREHOSE_BACKFILL_RETRIES: IntCounterVec = register_int_counter_vec!("vlpds_firehose_backfill_retries_total", "Cursor backfill retries: seek (a log seek re-run after retention pruned the log's head below the cursor under it), pruned (a whole backfill re-run for the same reason) or error (S3)", &["reason"]));
lazy!(FIREHOSE_EMIT_DELAY: Histogram = register_histogram!("vlpds_firehose_emit_delay_seconds", "Seq assignment of a merged batch's oldest event -> firehose emit", latency_buckets()));

pub fn export_firehose_config(merge_queue_bytes: usize, max_lag_bytes: usize) {
    FIREHOSE_MERGE_QUEUE_BUDGET.set(merge_queue_bytes as i64);
    FIREHOSE_MAX_LAG.set(max_lag_bytes as i64);
}
