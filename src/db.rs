use crate::models::ObservationSnapshot;
use rusqlite::{types::Type, Connection, Result as SqlResult};
use std::path::Path;

const SCHEMA_VERSION: i64 = 3;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        let db = Database { conn };
        db.conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        db.conn.busy_timeout(std::time::Duration::from_secs(5))?;
        db.restrict_file_permissions(path)?;
        db.init_schema()?;
        Ok(db)
    }

    fn restrict_file_permissions(&self, path: &Path) -> SqlResult<()> {
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        }
        Ok(())
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
                enabled INTEGER,
                active INTEGER,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );

            -- Legacy compatibility tables. The JSON snapshot is canonical;
            -- new snapshots are no longer duplicated into these tables.

            CREATE INDEX IF NOT EXISTS idx_snapshots_hostname_timestamp
                ON snapshots(hostname, timestamp);
            CREATE INDEX IF NOT EXISTS idx_listening_services_snapshot
                ON listening_services(snapshot_id);
            CREATE INDEX IF NOT EXISTS idx_network_connections_snapshot
                ON network_connections(snapshot_id);
            "#,
        )?;

        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if version < SCHEMA_VERSION {
            if version < 1 {
                self.conn.execute_batch("PRAGMA user_version = 1;")?;
            }
            if version < 2 {
                // Version 1 stored whole seconds. Migrate those keys before
                // switching to milliseconds to prevent same-second overwrites.
                self.conn.execute_batch(
                    "UPDATE snapshots SET timestamp = timestamp * 1000; PRAGMA user_version = 2;",
                )?;
            }
            if version < 3 {
                // Timer state can be unavailable when systemd does not expose
                // enabled/active fields. Preserve that uncertainty as NULL.
                self.conn.execute_batch(
                    "CREATE TABLE systemd_timers_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        unit TEXT NOT NULL,
                        enabled INTEGER,
                        active INTEGER,
                        FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
                    );
                    INSERT INTO systemd_timers_new (id, snapshot_id, name, unit, enabled, active)
                        SELECT id, snapshot_id, name, unit, enabled, active FROM systemd_timers;
                    DROP TABLE systemd_timers;
                    ALTER TABLE systemd_timers_new RENAME TO systemd_timers;
                    PRAGMA user_version = 3;",
                )?;
            }
        }
        Ok(())
    }

    pub fn store_snapshot(&mut self, snapshot: &ObservationSnapshot) -> SqlResult<()> {
        let snapshot_json = serde_json::to_string(&snapshot)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;

        let timestamp = snapshot.timestamp.timestamp_millis();
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO snapshots (hostname, timestamp, data)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(hostname, timestamp) DO UPDATE SET data = excluded.data",
            rusqlite::params![&snapshot.hostname, timestamp, snapshot_json],
        )?;

        tx.commit()?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_latest_snapshot(&self, hostname: &str) -> SqlResult<Option<ObservationSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM snapshots WHERE hostname = ?1
             ORDER BY timestamp DESC LIMIT 1",
        )?;

        let result = stmt.query_row(rusqlite::params![hostname], |row| row.get::<_, String>(0));

        match result {
            Ok(json) => {
                let snapshot = serde_json::from_str(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(error))
                })?;
                Ok(Some(snapshot))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_snapshots_since(
        &self,
        hostname: &str,
        since_timestamp: i64,
    ) -> SqlResult<Vec<ObservationSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM snapshots WHERE hostname = ?1 AND timestamp >= ?2
             ORDER BY timestamp ASC",
        )?;

        let snapshots = stmt
            .query_map(rusqlite::params![hostname, since_timestamp], |row| {
                let json = row.get::<_, String>(0)?;
                serde_json::from_str(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(error))
                })
            })?
            .collect::<SqlResult<Vec<ObservationSnapshot>>>()?;

        Ok(snapshots)
    }

    pub fn get_all_snapshots_since(
        &self,
        since_timestamp: i64,
    ) -> SqlResult<Vec<ObservationSnapshot>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM snapshots WHERE timestamp >= ?1 ORDER BY timestamp ASC")?;

        let snapshots = stmt
            .query_map(rusqlite::params![since_timestamp], |row| {
                let json = row.get::<_, String>(0)?;
                serde_json::from_str(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(error))
                })
            })?
            .collect::<SqlResult<Vec<ObservationSnapshot>>>()?;

        Ok(snapshots)
    }

    /// Bound long-running observation databases while retaining recent history.
    pub fn prune_snapshots_before(&mut self, cutoff_timestamp: i64) -> SqlResult<usize> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM listening_services
             WHERE snapshot_id IN (SELECT id FROM snapshots WHERE timestamp < ?1)",
            rusqlite::params![cutoff_timestamp],
        )?;
        tx.execute(
            "DELETE FROM network_connections
             WHERE snapshot_id IN (SELECT id FROM snapshots WHERE timestamp < ?1)",
            rusqlite::params![cutoff_timestamp],
        )?;
        tx.execute(
            "DELETE FROM cron_jobs
             WHERE snapshot_id IN (SELECT id FROM snapshots WHERE timestamp < ?1)",
            rusqlite::params![cutoff_timestamp],
        )?;
        tx.execute(
            "DELETE FROM systemd_timers
             WHERE snapshot_id IN (SELECT id FROM snapshots WHERE timestamp < ?1)",
            rusqlite::params![cutoff_timestamp],
        )?;
        let deleted = tx.execute(
            "DELETE FROM snapshots WHERE timestamp < ?1",
            rusqlite::params![cutoff_timestamp],
        )?;
        tx.commit()?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::models::*;
    use chrono::Utc;

    #[test]
    fn stores_snapshot_as_canonical_audit_record_without_normalized_duplicates() {
        let path =
            std::env::temp_dir().join(format!("screamless-db-test-{}.db", std::process::id()));
        let mut db = Database::new(&path).unwrap();
        let snapshot = ObservationSnapshot {
            timestamp: Utc::now(),
            hostname: "test-host".to_string(),
            host_identity: HostIdentity {
                hostname: "test-host".to_string(),
                ..HostIdentity::default()
            },
            listening_services: vec![ListeningService {
                port: 443,
                protocol: "tcp".to_string(),
                process_name: "web".to_string(),
                pid: 10,
                user: "1000".to_string(),
            }],
            network_connections: vec![],
            processes: vec![],
            cron_jobs: vec![CronJob {
                schedule: "0 2 * * *".to_string(),
                command: "[redacted]".to_string(),
                source: "/etc/crontab".to_string(),
            }],
            systemd_timers: vec![],
            dns_names: vec![],
            config_references: vec![],
            config_scan_audit: None,
            software: vec![],
            sampling_interval_seconds: None,
            privileges: "full".to_string(),
            probe_statuses: ProbeStatuses::default(),
        };

        db.store_snapshot(&snapshot).unwrap();
        let mut same_second = snapshot.clone();
        same_second.timestamp += chrono::Duration::milliseconds(1);
        db.store_snapshot(&same_second).unwrap();
        let listener_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM listening_services", [], |row| {
                row.get(0)
            })
            .unwrap();
        let cron_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM cron_jobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(listener_count, 0);
        assert_eq!(cron_count, 0);
        assert_eq!(db.get_snapshots_since("test-host", 0).unwrap().len(), 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reports_corrupt_snapshot_data_as_an_error() {
        let path =
            std::env::temp_dir().join(format!("screamless-db-corrupt-{}.db", std::process::id()));
        let db = Database::new(&path).unwrap();
        db.conn
            .execute(
                "INSERT INTO snapshots (hostname, timestamp, data) VALUES (?1, ?2, ?3)",
                rusqlite::params!["broken-host", 1_i64, "not-json"],
            )
            .unwrap();

        assert!(db.get_all_snapshots_since(0).is_err());
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn migrates_second_precision_snapshot_keys_to_milliseconds() {
        let path = std::env::temp_dir().join(format!(
            "screamless-db-migration-test-{}.db",
            std::process::id()
        ));
        let db = Database::new(&path).unwrap();
        drop(db);

        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute(
            "INSERT INTO snapshots (hostname, timestamp, data) VALUES (?1, ?2, ?3)",
            rusqlite::params!["legacy-host", 1_700_000_000_i64, "{}"],
        )
        .unwrap();
        raw.execute_batch("PRAGMA user_version = 1;").unwrap();
        drop(raw);

        let db = Database::new(&path).unwrap();
        let timestamp: i64 = db
            .conn
            .query_row(
                "SELECT timestamp FROM snapshots WHERE hostname = 'legacy-host'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(timestamp, 1_700_000_000_000_i64);
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
