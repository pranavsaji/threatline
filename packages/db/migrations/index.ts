/**
 * Forge SQL (MySQL-compatible TiDB) migrations. One statement per entry: Forge SQL runs one statement per query.
 * No foreign keys (unsupported). JSON payloads are stored as MEDIUMTEXT and validated with zod on read.
 */
export interface Migration {
  version: number;
  name: string;
  statements: string[];
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'v001_init',
    statements: [
      `CREATE TABLE IF NOT EXISTS reviews (
        id VARCHAR(40) PRIMARY KEY, issue_id VARCHAR(40) NOT NULL, issue_key VARCHAR(40) NOT NULL, revision INT NOT NULL,
        status VARCHAR(20) NOT NULL, context_hash VARCHAR(64) NOT NULL, risk_score INT NOT NULL, partial_bundle TINYINT NOT NULL,
        prompt_version VARCHAR(20) NOT NULL, model_ids TEXT NOT NULL, samples_expected INT NOT NULL, samples_received INT NOT NULL,
        tokens_in INT NOT NULL, tokens_out INT NOT NULL, failure_reason VARCHAR(200), created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL)`,
      `CREATE UNIQUE INDEX idx_reviews_issue_rev ON reviews (issue_id, revision)`,
      `CREATE INDEX idx_reviews_status ON reviews (status, updated_at)`,
      `CREATE TABLE IF NOT EXISTS review_stages (
        review_id VARCHAR(40) NOT NULL, stage VARCHAR(40) NOT NULL, status VARCHAR(20) NOT NULL, checkpoint_json MEDIUMTEXT,
        error VARCHAR(200), updated_at VARCHAR(30) NOT NULL, PRIMARY KEY (review_id, stage))`,
      `CREATE TABLE IF NOT EXISTS context_facts (
        review_id VARCHAR(40) NOT NULL, id VARCHAR(40) NOT NULL, position INT NOT NULL, source_ari VARCHAR(255) NOT NULL,
        trust_level VARCHAR(10) NOT NULL, injection_suspected TINYINT NOT NULL, fact_json MEDIUMTEXT NOT NULL, PRIMARY KEY (review_id, id))`,
      `CREATE TABLE IF NOT EXISTS threats (
        id VARCHAR(40) PRIMARY KEY, review_id VARCHAR(40) NOT NULL, position INT NOT NULL, state VARCHAR(20) NOT NULL,
        severity VARCHAR(10) NOT NULL, threat_json MEDIUMTEXT NOT NULL)`,
      `CREATE INDEX idx_threats_review ON threats (review_id)`,
      `CREATE TABLE IF NOT EXISTS review_discarded (review_id VARCHAR(40) PRIMARY KEY, discarded_json MEDIUMTEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS agent_samples (review_id VARCHAR(40) NOT NULL, n INT NOT NULL, sample_json MEDIUMTEXT NOT NULL, PRIMARY KEY (review_id, n))`,
      `CREATE TABLE IF NOT EXISTS requirements (
        id VARCHAR(40) PRIMARY KEY, issue_id VARCHAR(40) NOT NULL, status VARCHAR(20) NOT NULL, severity VARCHAR(10) NOT NULL,
        requirement_json MEDIUMTEXT NOT NULL)`,
      `CREATE INDEX idx_requirements_issue ON requirements (issue_id)`,
      `CREATE TABLE IF NOT EXISTS ledger (
        seq BIGINT PRIMARY KEY, event_type VARCHAR(40) NOT NULL, payload_json MEDIUMTEXT NOT NULL, actor VARCHAR(128) NOT NULL,
        prev_hash VARCHAR(64) NOT NULL, entry_hash VARCHAR(64) NOT NULL, created_at VARCHAR(30) NOT NULL)`,
      `CREATE UNIQUE INDEX idx_ledger_prev ON ledger (prev_hash)`,
      `CREATE TABLE IF NOT EXISTS feedback (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, threat_id VARCHAR(40) NOT NULL, component VARCHAR(255) NOT NULL, title VARCHAR(255) NOT NULL,
        stride VARCHAR(30) NOT NULL, actor VARCHAR(128) NOT NULL, action VARCHAR(20) NOT NULL, reason VARCHAR(30), note VARCHAR(2000))`,
      `CREATE INDEX idx_feedback_component ON feedback (component, action)`,
      `CREATE TABLE IF NOT EXISTS issues (
        issue_id VARCHAR(40) PRIMARY KEY, issue_key VARCHAR(40) NOT NULL, project_key VARCHAR(40) NOT NULL, parent_id VARCHAR(40))`,
      `CREATE INDEX idx_issues_key ON issues (issue_key)`,
      `CREATE INDEX idx_issues_parent ON issues (parent_id)`,
      `CREATE TABLE IF NOT EXISTS issue_pages (page_id VARCHAR(40) NOT NULL, issue_id VARCHAR(40) NOT NULL, PRIMARY KEY (page_id, issue_id))`,
      `CREATE TABLE IF NOT EXISTS attestations (
        id VARCHAR(40) PRIMARY KEY, issue_key VARCHAR(40) NOT NULL, repo VARCHAR(200) NOT NULL, commit_sha VARCHAR(40) NOT NULL,
        kid VARCHAR(64) NOT NULL, expires_at VARCHAR(30) NOT NULL, nonce VARCHAR(64) NOT NULL)`,
      `CREATE INDEX idx_attestations_issue ON attestations (issue_key)`,
      `CREATE TABLE IF NOT EXISTS usage_monthly (month VARCHAR(7) PRIMARY KEY, tokens_in BIGINT NOT NULL, tokens_out BIGINT NOT NULL, reviews INT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS posture_snapshots (day VARCHAR(10) PRIMARY KEY, snapshot_json MEDIUMTEXT NOT NULL)`,
    ],
  },
  {
    version: 2,
    name: 'merkle_heads',
    statements: [
      `CREATE TABLE IF NOT EXISTS merkle_heads (
        tree_size INT PRIMARY KEY, root_hash VARCHAR(64) NOT NULL, kid VARCHAR(64) NOT NULL, signature VARCHAR(128) NOT NULL,
        published_page_id VARCHAR(40), created_at VARCHAR(30) NOT NULL)`,
    ],
  },
  {
    version: 3,
    name: 'ledger_event_type_index',
    // Final review I5: verdict refreshes read acceptance, confirmation and break-glass events only, not every attestation.
    statements: [`CREATE INDEX idx_ledger_event_type ON ledger (event_type)`],
  },
  {
    version: 4,
    name: 'ledger_issue_index',
    // Scale: the panel and every verdict refresh read one work item's events, not the whole site's. Rows written before
    // this migration have no issue_id; reads include them, so nothing is missed and the cost stays bounded.
    statements: [`ALTER TABLE ledger ADD COLUMN issue_id VARCHAR(40)`, `CREATE INDEX idx_ledger_issue ON ledger (issue_id, event_type)`],
  },
  {
    version: 5,
    name: 'rate_limits_and_ledger_time_index',
    // Security: re-run limits are a conditional UPDATE on one row per account (or work item), so parallel re-runs
    // cannot all pass a read-then-write check. One row per bucket: the window column resets it, nothing accumulates.
    // Scale: the acceptance expiry sweep reads acceptance events of the last ~400 days by type and time, not all of them.
    statements: [
      `CREATE TABLE IF NOT EXISTS rate_limits (bucket VARCHAR(191) PRIMARY KEY, win VARCHAR(20) NOT NULL, used INT NOT NULL)`,
      `CREATE INDEX idx_ledger_type_time ON ledger (event_type, created_at)`,
    ],
  },
  {
    version: 7,
    name: 'suppression_rules',
    // Team learning: a project's suppression rules (immutable fields as JSON; status and who ended it as columns, so a
    // revoke or expiry is one conditional UPDATE), the work items each rule hid a threat on or was unhidden on, and the
    // work item and time of each dismissal (rows written before this have none and feed no suggestion).
    statements: [
      `CREATE TABLE IF NOT EXISTS suppression_rules (
        id VARCHAR(40) PRIMARY KEY, project_key VARCHAR(40) NOT NULL, status VARCHAR(10) NOT NULL, created_at VARCHAR(30) NOT NULL,
        expires_at VARCHAR(30) NOT NULL, ended_by VARCHAR(128), ended_at VARCHAR(30), end_reason VARCHAR(300), rule_json MEDIUMTEXT NOT NULL)`,
      `CREATE INDEX idx_suppression_rules_project ON suppression_rules (project_key, status, expires_at)`,
      `CREATE INDEX idx_suppression_rules_status ON suppression_rules (status, created_at)`,
      `CREATE TABLE IF NOT EXISTS suppression_matches (
        rule_id VARCHAR(40) NOT NULL, issue_id VARCHAR(40) NOT NULL, issue_key VARCHAR(40) NOT NULL, matched_at VARCHAR(30) NOT NULL,
        unhidden_by VARCHAR(128), unhidden_at VARCHAR(30), PRIMARY KEY (rule_id, issue_id))`,
      `CREATE INDEX idx_suppression_matches_issue ON suppression_matches (issue_id)`,
      `ALTER TABLE feedback ADD COLUMN issue_id VARCHAR(40)`,
      `ALTER TABLE feedback ADD COLUMN issue_key VARCHAR(40)`,
      `ALTER TABLE feedback ADD COLUMN project_key VARCHAR(40)`,
      `ALTER TABLE feedback ADD COLUMN created_at VARCHAR(30)`,
      `CREATE INDEX idx_feedback_action_time ON feedback (action, created_at)`,
    ],
  },
  {
    version: 8,
    name: 'threats_state_index',
    // Scale: the champion inbox reads the threats waiting for a champion (state needs_human) across the site through
    // this index instead of scanning every threat ever stored. Version 6 was never used (the Forge runner tracks steps by name, so the gap is harmless).
    statements: [`CREATE INDEX idx_threats_state ON threats (state, severity)`],
  },
];
