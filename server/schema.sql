CREATE TABLE IF NOT EXISTS stats (
  id         TEXT PRIMARY KEY,
  title      TEXT NOT NULL,
  choices    TEXT NOT NULL,           -- JSON: [{name, slot}, ...]
  owner_hash TEXT NOT NULL,           -- sha256(オーナートークン)
  created    INTEGER NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS records (
  id      TEXT NOT NULL,              -- クライアント発行(再送しても重複しない)
  stat_id TEXT NOT NULL,
  c       INTEGER NOT NULL,           -- 選択肢のindex
  ts      INTEGER NOT NULL,           -- 記録日時(ms)
  member  TEXT NOT NULL,              -- 匿名メンバーID
  nick    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (stat_id, id)
);

CREATE INDEX IF NOT EXISTS idx_records_stat ON records(stat_id, ts);
