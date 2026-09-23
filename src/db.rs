use rusqlite::{Connection, Result as SqlResult};
use crate::models::ObservationSnapshot;
use serde_json;
use std::path::Path;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        let db = Database { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                data TEXT NOT NULL,
                UNIQUE(hostname, timestamp)
            );

            CREATE TABLE IF NOT EXISTS listening_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                process_name TEXT NOT NULL,
                pid INTEGER NOT NULL,
                "user" TEXT NOT NULL,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );

            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                local_addr TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_addr TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );

            CREATE TABLE IF NOT EXISTS cron_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                schedule TEXT NOT NULL,
                command TEXT NOT NULL,
                source TEXT NOT NULL,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );

            CREATE TABLE IF NOT EXISTS systemd_timers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                unit TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                active INTEGER NOT NULL,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );
            "#,
        )?;
        Ok(())
    }

    pub fn store_snapshot(&self, snapshot: &ObservationSnapshot) -> SqlResult<()> {
        let snapshot_json = serde_json::to_string(&snapshot)
            .expect("Failed to serialize snapshot");

        let timestamp = snapshot.timestamp.timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO snapshots (hostname, timestamp, data)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![&snapshot.hostname, timestamp, snapshot_json],
        )?;

        Ok(())
    }

    pub fn get_latest_snapshot(&self, hostname: &str) -> SqlResult<Option<ObservationSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM snapshots WHERE hostname = ?1
             ORDER BY timestamp DESC LIMIT 1"
        )?;

        let result = stmt.query_row(
            rusqlite::params![hostname],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(json) => {
                let snapshot = serde_json::from_str(&json)
                    .expect("Failed to deserialize snapshot");
                Ok(Some(snapshot))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_snapshots_since(&self, hostname: &str, since_timestamp: i64) -> SqlResult<Vec<ObservationSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM snapshots WHERE hostname = ?1 AND timestamp >= ?2
             ORDER BY timestamp ASC"
        )?;

        let snapshots = stmt.query_map(
            rusqlite::params![hostname, since_timestamp],
            |row| row.get::<_, String>(0),
        )?
            .collect::<SqlResult<Vec<_>>>()?
            .into_iter()
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();

        Ok(snapshots)
    }
}
