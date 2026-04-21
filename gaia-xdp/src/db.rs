use anyhow::{Context, Result};
use serde::Serialize;
use tokio_rusqlite::{Connection, params};

use crate::EventRecord;

pub struct EventDb {
    conn: Connection,
}

/// Query filter for history endpoint.
#[derive(Debug, Default)]
pub struct EventFilter {
    pub kind: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub page: u32,
    pub page_size: u32,
}

/// A single event row returned from the DB.
#[derive(Debug, Clone, Serialize)]
pub struct StoredEvent {
    pub id: i64,
    pub ts_ms: i64,
    pub kind: String,
    pub action: String,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_port: Option<u16>,
}

/// Paginated query result.
#[derive(Debug, Serialize)]
pub struct EventPage {
    pub events: Vec<StoredEvent>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

impl EventDb {
    pub async fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .await
            .with_context(|| format!("open sqlite db at {path}"))?;

        conn.call(|c| {
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 CREATE TABLE IF NOT EXISTS events (
                   id       INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts_ms    INTEGER NOT NULL,
                   kind     TEXT NOT NULL,
                   action   TEXT NOT NULL,
                   pid      INTEGER NOT NULL,
                   tgid     INTEGER NOT NULL,
                   uid      INTEGER NOT NULL,
                   gid      INTEGER NOT NULL,
                   comm     TEXT NOT NULL,
                   detail   TEXT NOT NULL,
                   service  TEXT,
                   net_addr TEXT,
                   net_port INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
                 CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts_ms);",
            )?;
            Ok(())
        })
        .await
        .context("create events table")?;

        Ok(Self { conn })
    }

    /// Insert one event. Errors are intentionally ignored at the call site.
    pub async fn insert_event(&self, r: EventRecord) -> Result<()> {
        let net_addr = r.network.as_ref().map(|n| n.address.clone());
        let net_port: Option<i64> = r.network.as_ref().map(|n| n.port as i64);
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT INTO events
                       (ts_ms, kind, action, pid, tgid, uid, gid, comm, detail, service, net_addr, net_port)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![
                        r.timestamp_ns as i64,
                        r.kind,
                        r.action,
                        r.pid,
                        r.tgid,
                        r.uid,
                        r.gid,
                        r.comm,
                        r.detail,
                        r.service,
                        net_addr,
                        net_port,
                    ],
                )?;
                Ok(())
            })
            .await
            .context("insert event")?;
        Ok(())
    }

    pub async fn query_events(&self, filter: EventFilter) -> Result<EventPage> {
        let page_size = filter.page_size.clamp(1, 200);
        let offset = (filter.page * page_size) as i64;
        let limit = page_size as i64;

        self.conn
            .call(move |c| {
                // Build WHERE clause and a matching boxed params list so the
                // number of bound values always equals the number of placeholders.
                let mut conditions: Vec<String> = Vec::new();
                let mut filter_params: Vec<Box<dyn tokio_rusqlite::ToSql>> = Vec::new();

                if let Some(k) = filter.kind {
                    let n = filter_params.len() + 1;
                    conditions.push(format!("kind = ?{n}"));
                    filter_params.push(Box::new(k));
                }
                if let Some(s) = filter.since_ms {
                    let n = filter_params.len() + 1;
                    conditions.push(format!("ts_ms >= ?{n}"));
                    filter_params.push(Box::new(s));
                }
                if let Some(u) = filter.until_ms {
                    let n = filter_params.len() + 1;
                    conditions.push(format!("ts_ms <= ?{n}"));
                    filter_params.push(Box::new(u));
                }

                let where_clause = if conditions.is_empty() {
                    String::new()
                } else {
                    format!("WHERE {}", conditions.join(" AND "))
                };

                let fp: Vec<&dyn tokio_rusqlite::ToSql> =
                    filter_params.iter().map(|b| b.as_ref()).collect();

                // COUNT
                let count_sql = format!("SELECT COUNT(*) FROM events {where_clause}");
                let total: u64 = c.query_row(&count_sql, fp.as_slice(), |row| row.get(0))?;

                // DATA — LIMIT/OFFSET params follow the filter params
                let lim_idx = filter_params.len() + 1;
                let off_idx = filter_params.len() + 2;
                let data_sql = format!(
                    "SELECT id,ts_ms,kind,action,pid,tgid,uid,gid,comm,detail,service,net_addr,net_port
                     FROM events {where_clause}
                     ORDER BY ts_ms DESC, id DESC
                     LIMIT ?{lim_idx} OFFSET ?{off_idx}"
                );

                let mut all_params: Vec<&dyn tokio_rusqlite::ToSql> = fp.clone();
                all_params.push(&limit);
                all_params.push(&offset);

                let mut stmt = c.prepare(&data_sql)?;
                let events: Vec<StoredEvent> = stmt
                    .query_map(all_params.as_slice(), |row| {
                        let net_port_raw: Option<i64> = row.get(12)?;
                        Ok(StoredEvent {
                            id:       row.get(0)?,
                            ts_ms:    row.get(1)?,
                            kind:     row.get(2)?,
                            action:   row.get(3)?,
                            pid:      row.get::<_, i64>(4)? as u32,
                            tgid:     row.get::<_, i64>(5)? as u32,
                            uid:      row.get::<_, i64>(6)? as u32,
                            gid:      row.get::<_, i64>(7)? as u32,
                            comm:     row.get(8)?,
                            detail:   row.get(9)?,
                            service:  row.get(10)?,
                            net_addr: row.get(11)?,
                            net_port: net_port_raw.map(|v| v as u16),
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();

                Ok(EventPage { events, total, page: filter.page, page_size })
            })
            .await
            .context("query events")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventRecord, NetworkView};

    fn make_record(kind: &str, pid: u32, ts: u64) -> EventRecord {
        EventRecord {
            timestamp_ns: ts,
            kind: kind.to_string(),
            action: "enter".to_string(),
            pid,
            tgid: pid,
            uid: 0,
            gid: 0,
            comm: "test".to_string(),
            detail: format!("/test/{kind}"),
            network: None,
            service: None,
        }
    }

    #[tokio::test]
    async fn test_insert_and_query() {
        let db = EventDb::open(":memory:").await.unwrap();

        // Insert 10 events: 5 process, 5 privilege
        for i in 0u32..10 {
            let kind = if i % 2 == 0 { "process" } else { "privilege" };
            db.insert_event(make_record(
                kind,
                1000 + i,
                (i as u64) * 1000 + 1_700_000_000_000,
            ))
            .await
            .unwrap();
        }

        // Query all
        let page = db
            .query_events(EventFilter {
                page_size: 20,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.total, 10, "expected 10 total");
        assert_eq!(page.events.len(), 10);
        println!("total=10 ✓");

        // Filter by kind
        let page2 = db
            .query_events(EventFilter {
                kind: Some("process".into()),
                page_size: 20,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.total, 5, "expected 5 process events");
        assert!(page2.events.iter().all(|e| e.kind == "process"));
        println!("filter kind=process → 5 rows ✓");

        // Pagination
        let p0 = db
            .query_events(EventFilter {
                page: 0,
                page_size: 3,
                ..Default::default()
            })
            .await
            .unwrap();
        let p1 = db
            .query_events(EventFilter {
                page: 1,
                page_size: 3,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(p0.events.len(), 3);
        assert_eq!(p1.events.len(), 3);
        // Pages must not overlap
        let ids0: Vec<i64> = p0.events.iter().map(|e| e.id).collect();
        let ids1: Vec<i64> = p1.events.iter().map(|e| e.id).collect();
        assert!(
            ids0.iter().all(|id| !ids1.contains(id)),
            "pages must not overlap"
        );
        println!("pagination page0={ids0:?} page1={ids1:?} ✓");

        // Time range filter
        let since = 1_700_000_003_000i64; // after first 3 events
        let page3 = db
            .query_events(EventFilter {
                since_ms: Some(since),
                page_size: 20,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(page3.total <= 7, "expected ≤7 events after since_ms");
        assert!(page3.events.iter().all(|e| e.ts_ms >= since));
        println!("time range since={since} → {} rows ✓", page3.total);

        // Network event
        let mut net_rec = make_record("network", 2000, 1_700_000_099_000);
        net_rec.network = Some(NetworkView {
            address: "1.2.3.4".into(),
            port: 443,
        });
        db.insert_event(net_rec).await.unwrap();
        let net_page = db
            .query_events(EventFilter {
                kind: Some("network".into()),
                page_size: 5,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(net_page.total, 1);
        let ne = &net_page.events[0];
        assert_eq!(ne.net_addr.as_deref(), Some("1.2.3.4"));
        assert_eq!(ne.net_port, Some(443));
        println!("network event net_addr/port preserved ✓");

        println!("\nAll db tests passed ✓");
    }
}
