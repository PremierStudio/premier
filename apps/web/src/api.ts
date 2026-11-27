import type {
  PolicyIntent,
  PolicyTarget,
  ProposePolicyIntentResponse,
  SecretProbeInput,
  ServerOverrideCheck,
  ServerPolicyOverrideFinding,
} from "./lib/policyIntent";

export type {
  PolicyIntent,
  PolicyTarget,
  ProposePolicyIntentResponse,
  SecretProbeInput,
  ServerOverrideCheck,
  ServerPolicyOverrideFinding,
};

export interface IdentityPreset {
  id: string;
  label: string;
  subtitle: string;
  principal: string;
  /** Display only: the server resolves groups from the directory. */
  groups: string[];
  agentProfile?: string;
  badgeColor: "emerald" | "indigo" | "amber" | "zinc";
}

export interface DirectoryPrincipal {
  principal: string;
  display_name: string;
  groups: string[];
  is_owner: boolean;
  /** True when a user account signs in as this principal; false for policy-only principals. */
  has_account: boolean;
}

export interface Directory {
  principals: DirectoryPrincipal[];
  groups: string[];
}

export interface WorkspaceSettings {
  /** 1–3650, or null to keep audit events forever. */
  audit_retention_days: number | null;
  /** Newer servers, read-only: SSH clone base such as `ssh://git@host:7429`; null when unset. */
  ssh_public_url?: string | null;
}

export const GROUP_NAME_RE = /^[a-z0-9_-]{1,32}$/;

export interface HostSandboxCapabilities {
  os: string;
  arch: string;
  posix_fifo_supported: boolean;
  linux_bwrap_available: boolean;
  linux_unshare_available: boolean;
  linux_fuse3_available: boolean;
  windows_projfs_available: boolean;
}

/** Signed out, the server sends only `status` and `version`. */
export interface HealthResponse {
  status: string;
  version: string;
  os?: string;
  workspace_root?: string;
  policy_loaded?: boolean;
  server_policy_loaded?: boolean;
  schema_loaded?: boolean;
  host_capabilities?: HostSandboxCapabilities;
  /** "none": agent sessions are refused (501). "unsandboxed-allowed": they run without a sandbox. */
  agent_sandbox?: "bwrap" | "none" | "unsandboxed-allowed";
  /** Why the sandbox is not "bwrap", or what is weaker about it; empty when nothing is. */
  agent_sandbox_detail?: string;
  /** Whether the built-in SSH Git listener is enabled, and its port. */
  ssh_enabled?: boolean;
  ssh_port?: number;
}

export type TraceSpanKind =
  | "prompt_turn"
  | "tool_call"
  | "file_access"
  | "proxy_egress"
  | "error_diagnostic"
  | "delivery_report";

export type TraceSessionStatus = "active" | "completed" | "failed" | "blocked";

export type TraceIntegrityStatus = "live" | "verified" | "tampered";

export interface TraceIntegrityReport {
  status: TraceIntegrityStatus;
  verified_spans: number;
  head_hash?: string;
  detail?: string | null;
}

export interface TraceSpan {
  span_id: string;
  timestamp: string;
  kind: TraceSpanKind;
  summary: string;
  path?: string | null;
  zone?: string | null;
  tool_name?: string | null;
  command?: string | null;
  decision?: string | null;
  error_message?: string | null;
  bytes_scrubbed: number;
  duration_ms?: number | null;
  redacted_for_viewer: boolean;
  actor_id?: string | null;
  actor_type?: string | null;
  parent_span_id?: string | null;
  correlation_id?: string | null;
  links?: string[];
  status?: string | null;
  exit_code?: number | null;
  tokens_in?: number | null;
  tokens_out?: number | null;
  cost_usd_micros?: number | null;
  input?: unknown;
  output?: unknown;
  diff?: string | null;
  code_snippet?: string | null;
  language?: string | null;
  authority?: unknown;
  sequence?: number;
  source?: string | null;
  prev_hash?: string | null;
  event_hash?: string | null;
}

export interface TraceDeliverySummary {
  total_spans: number;
  error_count: number;
  blocked_count: number;
  bytes_scrubbed: number;
  files_touched: string[];
  duration_ms: number;
  total_tokens_in?: number;
  total_tokens_out?: number;
  total_cost_usd_micros?: number;
  actors?: string[];
  provenance_digest?: string;
  integrity?: TraceIntegrityReport;
}

export interface TraceSession {
  session_id: string;
  started_at: string;
  updated_at: string;
  principal: string;
  agent_profile?: string | null;
  model: string;
  tool_name: string;
  branch: string;
  change_id?: string | null;
  commit_oid?: string | null;
  status: TraceSessionStatus;
  spans: TraceSpan[];
  delivery: TraceDeliverySummary;
}

export interface TraceIngestResponse {
  ok: boolean;
  session_id: string;
  span: TraceSpan;
  bytes_scrubbed: number;
}

export interface MatchedRuleTrace {
  id: string;
  layer: "server" | "repo";
  effect: "allow" | "deny";
  capabilities: string[];
  reason?: string;
}

export interface RepoTreeEntry {
  path: string;
  kind: "file" | "dir";
  visibility_state: "visible" | "traverse_only" | "omitted";
  effective: string[];
  human_effective: string[];
  agent_effective?: string[];
  synthesized_traverse: boolean;
  is_instruction_file: boolean;
  /** Absent or empty for members: rule traces are owner-only. */
  matched_rules?: MatchedRuleTrace[];
}

export interface RepoTreeResponse {
  principal: string;
  agent_profile?: string;
  ref_name: string;
  xray: boolean;
  visible_count: number;
  traverse_only_count: number;
  omitted_count: number;
  entries: RepoTreeEntry[];
}

export interface RepoFileResponse {
  path: string;
  allowed: boolean;
  content?: string;
  truncated: boolean;
  binary?: boolean;
  tip_oid?: string | null;
  reason: string;
}

export interface ExplainDecision {
  path: string;
  ref_name: string;
  principal: string;
  agent_profile?: string;
  effective: number;
  human_effective: number;
  agent_effective?: number;
  synthesized_traverse: boolean;
  matched_rules?: MatchedRuleTrace[];
}

export interface ExplainSecretEntry {
  name: string;
  sensitivity: "public" | "internal" | "secret" | "restricted";
  zone?: string;
  can_use: boolean;
  has_egress: boolean;
  approval?: "auto" | "jit";
}

export interface ExplainSecretsResponse {
  entries: ExplainSecretEntry[];
}

export interface PolicySummaryResponse {
  /** Owners: the imported in-repo policy is shown but not enforced until applied. */
  imported_policy_pending?: boolean;
  policy_loaded: boolean;
  server_policy_loaded: boolean;
  /** Empty for members: only owners get the policy text. */
  repo_policy_toml: string;
  server_policy_toml: string;
  /** Null for members. */
  policy?: unknown;
}

/** Names declared under `[[agent_profiles]]` in the policy; empty for members (no policy text). */
export function agentProfileNames(summary: PolicySummaryResponse): string[] {
  const profiles = (summary.policy as { agent_profiles?: unknown } | null | undefined)
    ?.agent_profiles;
  if (!Array.isArray(profiles)) return [];
  return profiles
    .map((p: unknown) => (p as { name?: unknown } | null)?.name)
    .filter((n): n is string => typeof n === "string" && n !== "");
}

export interface AccessDelta {
  principal: string;
  agent_profile?: string;
  path: string;
  before: string[];
  after: string[];
  granted: string[];
  revoked: string[];
}

export interface QuarantineAlert {
  path: string;
  severity: string;
  message: string;
}

export interface McpAccessDelta {
  principal: string;
  agent_profile?: string;
  tool: string;
  before_allowed: boolean;
  after_allowed: boolean;
  before_approval: "auto" | "jit" | "deny";
  after_approval: "auto" | "jit" | "deny";
  escalated: boolean;
}

export interface AccessImpactDiff {
  ref_name: string;
  deltas: AccessDelta[];
  quarantine_alerts: QuarantineAlert[];
  mcp_deltas?: McpAccessDelta[];
}

export type AuditDecision =
  | "allowed"
  | "denied"
  | "exfiltration_blocked"
  | "redacted"
  | "approval_required"
  | "rate_limited"
  | "budget_exceeded";

export type BudgetAction = "pause" | "terminate";

export interface AutonomyBudget {
  max_files_modified?: number | null;
  max_lines_changed?: number | null;
  max_workspace_bytes?: number | null;
  max_egress_requests?: number | null;
  max_egress_bytes?: number | null;
  max_jit_requests?: number | null;
  max_denied_attempts?: number | null;
  max_memory_mb?: number | null;
  max_pids?: number | null;
  max_cpu_secs?: number | null;
  on_budget_exceeded?: BudgetAction;
}

export interface BudgetSnapshot {
  limits: AutonomyBudget;
  files_modified: number;
  lines_changed: number;
  workspace_bytes: number;
  egress_requests: number;
  egress_bytes: number;
  jit_requests: number;
  denied_attempts: number;
  bytes_scrubbed: number;
  elapsed_secs: number;
  max_secs: number;
  paused: boolean;
  terminated: boolean;
  breached_metric?: string;
  breach_reason?: string;
}

export interface BudgetAlert {
  session_id: string;
  principal: string;
  agent_profile?: string;
  metric: string;
  current: number;
  limit: number;
  action: BudgetAction;
  message: string;
  timestamp: string;
}

export interface RaiseBudgetRequest {
  limits: AutonomyBudget;
  resume?: boolean;
}

export interface KeyTransparencyEntry {
  seq: number;
  timestamp: string;
  repo_id: string;
  vault_path: string;
  recipients: string[];
  recipients_fingerprint: string;
  actor: string;
  event: string;
  prev_hash: string;
  entry_hash: string;
}

export interface KmsStatus {
  mode: string;
  provider: string;
  key_id: string;
  envelope_version: number;
  dek_version: number;
  kek_separated: boolean;
  vault_path: string;
  entry_count: number;
  kt_enabled: boolean;
  kt_entries: number;
  kt_valid: boolean;
  kt_error?: string | null;
  kt_recent_entries?: KeyTransparencyEntry[];
}

export interface RotationSpec {
  provider?: string | null;
  webhook_url: string;
  signing_secret_ref: string;
  max_age_days?: number | null;
  schedule?: string | null;
  revoke_on_offboard: boolean;
}

export type RotationPhase = "prepare" | "commit" | "rollback";
export type RotationStatus = "committed" | "rolled_back" | "failed" | "manual_required";

export interface RotationReceipt {
  id: string;
  var_name: string;
  env: string;
  provider: string;
  webhook_url?: string | null;
  status: RotationStatus;
  phase_reached: RotationPhase;
  triggered_by_offboard: boolean;
  actor: string;
  reason: string;
  timestamp: string;
  http_status?: number | null;
  rollback_sent: boolean;
  error?: string | null;
}

export interface OidcDiscoveryDocument {
  issuer: string;
  jwks_uri: string;
  token_endpoint: string;
  response_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  token_ttl_default_secs: number;
  token_ttl_max_secs: number;
  kid: string;
  claims_supported: string[];
}

export interface ActorClaim {
  sub: string;
  profile: string;
  task_id: string;
}

export interface WorkloadClaims {
  iss: string;
  sub: string;
  act?: ActorClaim | null;
  aud: string[];
  repo: string;
  branch: string;
  scope: string[];
  groups: string[];
  iat: number;
  exp: number;
  jti: string;
}

export interface IssuedWorkloadToken {
  token: string;
  claims: WorkloadClaims;
  kid: string;
  alg: string;
}

export interface MintOidcTokenRequest {
  principal?: string;
  agent_profile?: string | null;
  task_id?: string | null;
  audience: string[];
  branch?: string;
  ttl_secs?: number;
}

export interface VerifyOidcResponse {
  valid: boolean;
  claims?: WorkloadClaims | null;
  error?: string | null;
}

export interface OffboardRequest {
  principal: string;
  reason?: string;
  env?: string;
  rotate_secrets?: boolean;
  delete_account?: boolean;
}

export interface OffboardReceipt {
  id: string;
  principal: string;
  actor: string;
  reason: string;
  timestamp: string;
  account_disabled: boolean;
  account_deleted: boolean;
  sessions_revoked: number;
  tokens_revoked: number;
  ssh_keys_revoked: number;
  approvals_revoked: number;
  agent_sessions_terminated: number;
  oidc_revoked: boolean;
  rotations: RotationReceipt[];
}

export interface AuditEvent {
  timestamp: string;
  principal: string;
  agent_profile?: string;
  agent_task_id?: string;
  component: string;
  action: string;
  target?: string;
  capability?: string;
  decision: AuditDecision;
  reason: string;
  bytes_scrubbed: number;
}

export type RiskLevel = "read_only" | "state_mutation" | "sensitive_scope";
export type GrantScope = "once" | "exact_path" | "read_only_prefix" | "exact_scope";

export interface SanitizedHeader {
  name: string;
  value: string;
  contains_placeholder: boolean;
}

export interface WirePreview {
  method: string;
  host: string;
  concrete_path: string;
  query_keys: string[];
  headers: SanitizedHeader[];
  body_preview?: string;
  body_size_bytes: number;
  body_truncated: boolean;
  body_is_binary: boolean;
}

export interface SessionContext {
  session_id?: string;
  branch?: string;
  command?: string;
}

export interface PendingApproval {
  id: string;
  principal: string;
  agent_profile?: string;
  var_name: string;
  host: string;
  method: string;
  path: string;
  ttl_secs: number;
  status: "pending" | "approved" | "denied" | "expired";
  created_at: string;
  decided_at?: string;
  expires_at?: string;
  kind?: "egress" | "mcp_tool";
  mcp_server?: string;
  mcp_tool?: string;
  risk?: "read" | "write" | "destructive";
  args_summary?: string;
  concrete_path?: string;
  risk_level?: RiskLevel;
  intent_summary?: string;
  wire_preview?: WirePreview;
  session_context?: SessionContext;
  sensitivity?: string;
  grant_scope?: GrantScope;
  denial_reason?: string;
}

export interface ApprovalDecisionOptions {
  grant_scope?: GrantScope;
  denial_reason?: string;
}

export interface PolicySuggestion {
  id: string;
  var_name: string;
  agent_profile: string;
  host: string;
  method: string;
  path_prefix: string;
  approved_count: number;
  threshold: number;
  summary: string;
  toml_snippet: string;
  last_approved_at: string;
}

/** Mirror of the server's `suggested_path_prefix`: the prefix a knock's approvals are tallied under. */
export function suggestedPathPrefix(schemaPrefix: string, concretePath?: string): string {
  if (schemaPrefix !== "/") return schemaPrefix;
  const seg = (concretePath ?? "").split(/[?#]/)[0].split("/").find((s) => s !== "");
  return seg && seg !== "." && seg !== ".." && !/[\s"\\\p{Cc}]/u.test(seg) ? `/${seg}/` : "/";
}

/** The living-policy proposal a pending knock would graduate, if any. */
export function suggestionForApproval(
  suggestions: PolicySuggestion[],
  ap: PendingApproval,
): PolicySuggestion | undefined {
  const prefix = suggestedPathPrefix(ap.path, ap.concrete_path);
  return suggestions.find(
    (s) =>
      s.var_name === ap.var_name &&
      s.host === ap.host.trim().toLowerCase() &&
      s.agent_profile === (ap.agent_profile ?? "").trim() &&
      s.method.toUpperCase() === ap.method.toUpperCase() &&
      s.path_prefix === prefix,
  );
}

export interface PolicySuggestionPreview {
  suggestion: PolicySuggestion;
  schema_path: string;
  before_toml: string;
  after_toml: string;
  unified_diff: string;
  already_covered: boolean;
}

export interface ApplySuggestionResponse {
  ok: boolean;
  suggestion_id: string;
  schema_path: string;
  commit: string;
}

export interface EgressSpec {
  hosts: string[];
  methods: string[];
  path_prefixes: string[];
  upstream_base_url?: string;
  inject?: { kind: string; header?: string; param?: string; prefix?: string };
  rate_limit_per_min?: number;
  approval: "auto" | "jit";
  jit_ttl_secs: number;
}

export interface VarSpec {
  type: string;
  sensitivity: "public" | "internal" | "secret" | "restricted";
  required_in: string[];
  default?: string;
  allowed_values: string[];
  zone?: string;
  description?: string;
  egress?: EgressSpec;
  mcp_servers?: string[];
  rotation?: RotationSpec | null;
}

export interface McpCredentialStatus {
  secret: string;
  inject: string;
  can_use: boolean;
  declared_in_schema: boolean;
}

export interface McpMatchedRuleTrace {
  id: string;
  layer: "server" | "repo";
  effect: "allow" | "deny";
  agent_scoped: boolean;
  reason?: string;
}

export type McpPinStatus = "pinned" | "tofu" | "unverified" | "quarantined";

export interface McpToolPermission {
  server: string;
  tool: string;
  full_name: string;
  description?: string;
  allowed: boolean;
  human_allowed: boolean;
  agent_allowed?: boolean;
  risk: "read" | "write" | "destructive";
  approval: "auto" | "jit" | "deny";
  jit_ttl_secs: number;
  pin_status: McpPinStatus;
  schema_hash?: string;
  arg_constraints: string[];
  required_secrets: string[];
  reason: string;
  matched_rules?: McpMatchedRuleTrace[];
}

export interface McpServerSummary {
  name: string;
  transport: "stdio" | "http_sse";
  description?: string;
  zone?: string;
  default_approval?: "auto" | "jit" | "deny";
  jit_ttl_secs: number;
  pin_on_first_use: boolean;
  pinned_tool_count: number;
  quarantined_count: number;
  credentials: McpCredentialStatus[];
  tools: McpToolPermission[];
}

export interface McpGatewaysResponse {
  principal: string;
  agent_profile?: string;
  ref_name: string;
  total_servers: number;
  allowed_tools: number;
  jit_tools: number;
  denied_tools: number;
  quarantined_alerts: number;
  servers: McpServerSummary[];
}

export interface McpDriftAlert {
  id: string;
  server: string;
  tool: string;
  full_name: string;
  kind: "policy_pin_mismatch" | "rug_pull_detected" | "tool_poisoning_heuristic" | string;
  severity: "critical" | "high" | string;
  message: string;
  expected_hash?: string;
  observed_hash: string;
  expected_description?: string;
  observed_description?: string;
  quarantined: boolean;
  detected_at: string;
  resolved_at?: string;
  resolved_by?: string;
}

export type McpArgConstraint =
  | {
      kind: "path_zone";
      arg: string;
      capability: string;
      allow_globs: string[];
      deny_globs: string[];
    }
  | {
      kind: "pattern";
      arg: string;
      allow_patterns: string[];
      deny_patterns: string[];
      case_insensitive: boolean;
    }
  | { kind: "allowed_values"; arg: string; values: string[] }
  | { kind: "forbid_arg"; arg: string };

export interface McpExplainResponse {
  decision: {
    server: string;
    tool: string;
    full_name: string;
    principal: string;
    agent_profile?: string;
    allowed: boolean;
    human_allowed: boolean;
    agent_allowed?: boolean;
    risk: "read" | "write" | "destructive";
    approval: "auto" | "jit" | "deny";
    jit_ttl_secs: number;
    required_secrets: string[];
    arg_constraints: McpArgConstraint[];
    matched_rules: McpMatchedRuleTrace[];
    reason: string;
  };
  pin_status: McpPinStatus;
  schema_hash?: string;
  arg_valid: boolean;
  arg_errors: string[];
  credentials: McpCredentialStatus[];
}

export interface EnvSchema {
  version: number;
  repo_id?: string;
  vars: Record<string, VarSpec>;
}

export interface ValidationIssue {
  var_name: string;
  message: string;
}

export interface ValidationReport {
  environment: string;
  checked_vars: number;
  issues: ValidationIssue[];
}

export interface SchemaDashboardResponse {
  /** Null or absent when the repository has no .env.schema. */
  schema?: EnvSchema | null;
  reports: Record<string, ValidationReport>;
  /** Server-evaluated capability decisions (`use` / `read`) per variable for the requested identity. */
  can_use?: Record<string, boolean>;
}

export interface OverlayEntry {
  kind: { kind: "team"; name: string } | { kind: "personal" };
  path: string;
  /** True when the overlay's payload is sealed with AES-256-GCM in the state dir. */
  encrypted: boolean;
  /** Owning principal of a personal overlay (per-user state). */
  owner_principal?: string | null;
  /** Directory group that owns a team overlay. */
  team_group?: string | null;
  /** Whether a payload is stored in the state dir (vs. a mount with no content yet). */
  has_payload?: boolean;
}

export interface OverlayManifest {
  version: number;
  entries: OverlayEntry[];
}

export interface OverlayCheckResponse {
  allowed: boolean;
  blocked_paths: string[];
  message: string;
}

export type Visibility =
  | { scope: "public" }
  | { scope: "org" }
  | { scope: "restricted"; allow: string[] }
  | { scope: "personal"; allow: string[] };

export interface BranchRecord {
  name: string;
  head_oid: string;
  subject: string;
  visibility: Visibility;
  readiness: "wip" | "ready";
  is_current: boolean;
  ahead_commits: number;
  private_paths_touched: string[];
}

export interface ProjectionAttestation {
  canonical_ref: string;
  policy_fingerprint: string;
  declassified: boolean;
  generated_at?: string;
}

export type FirewallSeverity = "info" | "warning" | "high" | "critical";
export type FindingCategory =
  | "metadata_leak"
  | "snippet_leak"
  | "vault_secret_leak"
  | "secret_pattern_leak"
  | "instruction_quarantine"
  | "policy_blocked";

export interface FirewallFinding {
  id: string;
  category: FindingCategory;
  severity: FirewallSeverity;
  blocking: boolean;
  location: string;
  line?: number;
  summary: string;
  owner_detail?: string;
  rule_id: string;
  sensitive_source: boolean;
}

export interface DeclassificationReport {
  passed: boolean;
  blocking_count: number;
  warning_count: number;
  report_digest: string;
  findings: FirewallFinding[];
  redacted?: boolean;
}

export interface QuarantineFileStatus {
  path: string;
  sha256: string;
  pinned_sha256?: string | null;
  approved_sha256?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  status: "pinned" | "approved" | "flagged" | "unverified";
  findings: FirewallFinding[];
}

export interface PendingQuarantineEdit {
  id: string;
  path: string;
  branch: string;
  proposed_by: string;
  agent_profile?: string | null;
  proposed_sha256: string;
  proposed_content: string;
  base_sha256?: string | null;
  commit_message: string;
  findings: FirewallFinding[];
  created_at: string;
  status: "pending" | "approved" | "rejected";
  decided_by?: string | null;
  decided_at?: string | null;
  decision_reason?: string | null;
}

export interface FirewallOverrideRecord {
  id: string;
  action: string;
  target: string;
  owner: string;
  reason: string;
  report_digest: string;
  finding_ids: string[];
  created_at: string;
}

export interface QuarantineOverviewResponse {
  enforced: boolean;
  tracked_files: QuarantineFileStatus[];
  pending_edits: PendingQuarantineEdit[];
  recent_overrides: FirewallOverrideRecord[];
}

export interface PublicDiffFile {
  path: string;
  kind: "added" | "modified" | "deleted";
  old_mode?: string | null;
  new_mode?: string | null;
  three_way_merged: boolean;
  is_instruction_file: boolean;
  binary: boolean;
  truncated: boolean;
  additions: number;
  deletions: number;
  patch: string;
}

export interface HeldBackRuleInfo {
  reason: string;
  rule_id?: string | null;
  layer?: "server" | "repo" | null;
  zones: string[];
}

export interface CollapsedCommitInfo {
  short_oid: string;
  subject: string;
  touches_public: boolean;
}

export interface SquashPreviewResponse {
  source_branch: string;
  target_branch: string;
  source_oid?: string;
  target_oid?: string;
  private_commits_collapsed: number;
  /** Paths a publish would add, change or delete on the target. */
  published_paths: string[];
  /** Paths cleanly 3-way merged between source and target. */
  merged_paths?: string[];
  /** Changed paths a publish holds back (the target keeps its own version). */
  scrubbed_paths: string[];
  /** Paths changed on both branches since they diverged; a publish is refused while any exist. */
  conflicts: string[];
  /** Conflicting paths this account may not list. */
  hidden_conflicts: number;
  /** False when there are conflicts. */
  declassification_gate_passed: boolean;
  attestation?: ProjectionAttestation;
  attestation_trailer: string;
  clean_commit_message: string;
  /** Newer servers: the rule that decides what is published, in the server's words. */
  publish_rule?: string;
  /** Newer servers: why each held-back path stays private (a map, or `{path, reason}` rows). */
  held_back_reasons?: Record<string, string> | { path: string; reason: string }[];
  /** Newer servers: files holding private content copied to a public path; a publish is refused. */
  blocked?: string[];
  hidden_blocked?: number;
  /** Newer servers: why a publish would be refused right now. */
  reason?: string;
  /** Declassification firewall scan report for the proposed publish. */
  declassification_report?: DeclassificationReport;
  /** Airlock inspection fields. */
  public_commits_collapsed?: number;
  collapsed_commits?: CollapsedCommitInfo[];
  source_head_oid?: string | null;
  target_head_oid?: string | null;
  source_commit_oid?: string | null;
  target_commit_oid?: string | null;
  three_way_merged_paths?: string[];
  quarantine_paths?: string[];
  overlay_blocked_paths?: string[];
  held_back_rules?: Record<string, HeldBackRuleInfo>;
  restricted_zones?: string[];
  public_diff?: PublicDiffFile[];
  public_diff_truncated?: boolean;
}

export interface PromptProvenance {
  session_visible: boolean;
  agent_profile: string;
  model: string;
  prompt_summary: string;
  tool_calls: string[];
  redaction_reason?: string;
  steps?: ProvenanceStep[];
  session_id?: string;
  sandbox?: string;
  bytes_scrubbed?: number;
  egress_calls?: number;
  egress_blocked?: number;
  exit_code?: number;
  created_at?: string;
}

export interface ProvenanceStep {
  seq: number;
  kind:
    | "session_start"
    | "command_exec"
    | "file_change"
    | "egress_request"
    | "egress_scrub"
    | "egress_blocked"
    | "jit_approval"
    | "auto_rebase"
    | "lane_conflict"
    | "round_commit"
    | "session_exit"
    | string;
  timestamp: string;
  summary: string;
  path?: string | null;
  target?: string | null;
  decision?: string | null;
  exit_code?: number | null;
  bytes_scrubbed?: number;
}

export interface ConflictHunk {
  start_line: number;
  end_line: number;
  base_lines: string[];
  ours_lines: string[];
  theirs_lines: string[];
  markers: string;
}

export interface LaneConflict {
  path: string;
  kind:
    | "content_overlap"
    | "modify_delete"
    | "delete_modify"
    | "add_add"
    | "binary_conflict"
    | "mode_conflict"
    | "path_type_collision"
    | string;
  summary: string;
  hunks: ConflictHunk[];
  allowed: boolean;
}

export interface AgentLane {
  lane_id: string;
  lane_ref: string;
  base_branch: string;
  parent_lane_id?: string | null;
  change_id?: string | null;
  base_commit?: string | null;
  tip_oid?: string | null;
  owner: string;
  agent_profile: string;
  visibility: Visibility;
  status: "active" | "rebased" | "conflicted" | "merged" | "discarded" | string;
  conflicts: LaneConflict[];
  last_session_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface InterdiffFile {
  path: string;
  status: string;
  allowed: boolean;
  additions: number;
  deletions: number;
  binary: boolean;
  patch: string;
}

export interface ReviewInterdiffResponse {
  change_id: string;
  from_round: number;
  to_round: number;
  from_oid: string;
  to_oid: string;
  rebased_between_rounds: boolean;
  upstream_files_skipped: number;
  hidden_files: number;
  files: InterdiffFile[];
}

export interface SteerReviewRequest {
  comment_ids?: string[];
  instruction?: string;
  command?: string;
  agent_profile?: string;
  auto_commit?: boolean;
  mark_changes_requested?: boolean;
  max_secs?: number;
}

export interface SteerReviewResponse {
  change_id: string;
  target_round: number;
  lane_id: string;
  session: AgentSessionRecord;
  packaged_comments: number;
  redacted_comments: number;
  packaged_conflicts: number;
}

export interface LaneRebaseResponse {
  lane: AgentLane;
  rebased: boolean;
  merged_paths: string[];
  conflicts: LaneConflict[];
  cascaded_lanes?: AgentLane[];
}

export interface LaneResolveResponse {
  lane: AgentLane;
  commit_oid?: string | null;
  review_round?: number | null;
}

export interface CommitSessionResponse {
  commit: string;
  branch?: string;
  rebased?: boolean;
  lane_id?: string | null;
  review_round?: number | null;
  session_id?: string;
  sandbox?: string;
  bytes_scrubbed?: number;
  egress_calls?: number;
  egress_blocked?: number;
  exit_code?: number;
  created_at?: string;
}

export interface ReviewDiffHunk {
  id: string;
  path: string;
  zone: string;
  header: string;
  allowed: boolean;
  lines: string[];
  /** Omitted by newer servers when `provenance_hidden` is set. */
  provenance?: PromptProvenance;
  /** Newer servers: the viewer is neither owner nor the session's principal. */
  provenance_hidden?: boolean;
}

export interface ReviewRound {
  round: number;
  commit_oid: string;
  label: string;
  created_at: string;
  rebased_cleanly: boolean;
  interdiff_summary: string;
  hunks: ReviewDiffHunk[];
  session_id?: string | null;
  steering_prompt?: string | null;
  addressed_comment_ids?: string[];
  conflicts?: LaneConflict[];
}

export interface GitCommitSummary {
  oid: string;
  short_oid: string;
  subject: string;
  author: string;
  relative_time: string;
  files_changed: number;
  /** Newer servers: the commit time; one of these, whichever the server sends. */
  date?: string;
  committed_at?: string;
  timestamp?: string;
}

export interface GitCommitFileDiff {
  path: string;
  allowed: boolean;
  patch: string;
  zone?: string;
}

export interface GitCommitDiffResponse {
  oid: string;
  subject: string;
  author: string;
  date: string;
  files: GitCommitFileDiff[];
  /** Files this identity cannot list; they are left out of `files`. */
  hidden_files: number;
}

export interface ReviewComment {
  id: string;
  author: string;
  path: string;
  line?: number;
  side?: "old" | "new" | null;
  body: string;
  created_at: string;
  round?: number | null;
  addressed_in_round?: number | null;
  kind?: "comment" | "steer";
  target_agent?: string | null;
  steer_session_id?: string | null;
}

export interface StoredReview {
  change_id: string;
  title: string;
  branch: string;
  base_ref?: string;
  author: string;
  delegated_agent?: string | null;
  visibility: Visibility;
  readiness: "wip" | "ready";
  round_oids?: string[];
  comments: ReviewComment[];
  verdicts: Record<string, string>;
}

export interface ChangeReviewRecord {
  change_id: string;
  title: string;
  branch: string;
  base_ref?: string;
  author: string;
  delegated_agent?: string;
  session_id?: string | null;
  visibility: Visibility;
  readiness: "wip" | "ready";
  quarantine_flagged: boolean;
  comments: ReviewComment[];
  verdicts: Record<string, string>;
  rounds: ReviewRound[];
  lane_id?: string | null;
  lane_status?: string | null;
  lane_conflicts?: LaneConflict[];
}

export interface SearchHit {
  path: string;
  line: number;
  text: string;
}

export interface RepoSearchResponse {
  query: string;
  total_hits: number;
  files_scanned: number;
  hits: SearchHit[];
}

export interface BlameLine {
  line: number;
  oid: string;
  author: string;
  date: string;
  summary: string;
}

export interface RepoBlameResponse {
  path: string;
  allowed: boolean;
  lines: BlameLine[];
}

export interface WriteRepoFileResponse {
  path: string;
  bytes_written: number;
  /** Oid of the commit the save created. */
  commit?: string;
}

export interface UpdateRepoPolicyResponse {
  ok: boolean;
  persisted_path?: string;
  rule_count: number;
  /** Oid of the commit on the default branch, when the apply created one. */
  commit?: string;
}

/** Abbreviated oid for display. */
export const shortOid = (oid: string): string => oid.slice(0, 7);

export interface CreateBranchResponse {
  name: string;
  full_ref: string;
  oid: string;
  visibility: Visibility;
  readiness: "wip" | "ready";
}

export interface PublishBranchResponse {
  new_commit_oid: string;
  target_ref: string;
  published_paths: string[];
  merged_paths?: string[];
  scrubbed_paths: string[];
  attestation_trailer: string;
  /** Newer servers: the message of the commit the publish created. */
  commit_message?: string;
  published_at?: string;
  actor?: string;
  policy_fingerprint?: string;
}

export interface SecretMetaEntry {
  env: string;
  backend: string;
  updated_at: string;
  rotated_count: number;
}

export interface SecretStatusResponse {
  vault_path: string;
  entries: Record<string, SecretMetaEntry>;
}

export type HygieneCategory =
  | "unzoned_directory"
  | "overlay_leak"
  | "stale_private_branch"
  | "missing_vault_secret"
  | "broad_egress_host";

export type HygieneSeverity = "attention" | "notice";

export type HygieneAction =
  | { kind: "draft_policy_rule"; zone_name: string; path_glob: string; toml_snippet: string }
  | { kind: "add_overlay_guard"; path: string; suggested_scope: string }
  | { kind: "configure_secret"; env: string; var_name: string }
  | { kind: "inspect_branch"; branch: string }
  | { kind: "review_agent_egress"; profile: string; hosts: string[] };

export interface HygieneInsight {
  id: string;
  category: HygieneCategory;
  severity: HygieneSeverity;
  target: string;
  title: string;
  detail: string;
  dismissed: boolean;
  dismissed_at?: string | null;
  action?: HygieneAction | null;
}

export interface HygieneInsightsResponse {
  ref_name: string;
  generated_at: string;
  active_count: number;
  dismissed_count: number;
  insights: HygieneInsight[];
}

export type SessionInsightKind =
  | "repeated_blocks"
  | "error_loop_churn"
  | "approaching_time_limit"
  | "approaching_size_limit";

export interface SessionInsight {
  id: string;
  session_id: string;
  kind: SessionInsightKind;
  severity: "attention" | "notice";
  title: string;
  detail: string;
  observed_at: string;
  metric_value: number;
  threshold: number;
}

export interface SessionCheckpoint {
  id: string;
  label: string;
  created_at: string;
  author: string;
  edited_paths: string[];
}

export interface SessionWorkspaceFileEntry {
  path: string;
  size: number;
  can_write: boolean;
  change_kind?: "added" | "modified" | null;
}

export interface SessionWorkspaceFilesResponse {
  session_id: string;
  branch: string;
  truncated: boolean;
  files: SessionWorkspaceFileEntry[];
}

export interface SessionWorkspaceFileResponse {
  path: string;
  content: string | null;
  size: number;
  binary: boolean;
  can_write: boolean;
  sha256: string;
}

export interface SessionWorkspaceWriteResponse {
  path: string;
  bytes_written: number;
  session: AgentSessionRecord;
}

export interface SessionCheckpointResponse {
  checkpoint: SessionCheckpoint;
  session: AgentSessionRecord;
}

export interface AgentSessionRecord {
  id: string;
  principal: string;
  agent_profile: string;
  env: string;
  command: string;
  proxy_url: string;
  placeholders: Record<string, string>;
  status: string;
  exit_code?: number;
  bytes_scrubbed: number;
  started_at: string;
  finished_at?: string;
  output_lines: string[];
  /** "exit code N", "timeout", "killed", or why the session never started. */
  ended_reason?: string | null;
  /** "none": the session ran as a plain process of the server user, not confined. */
  sandbox?: "bwrap" | "none" | "";
  /** The branch the private workspace was taken from, and its tip then. */
  branch?: string;
  base_commit?: string | null;
  /** What the session changed in its workspace, known once it has ended. */
  changes?: SessionChange[];
  /** The change set is incomplete: it cannot be committed. */
  changes_truncated?: boolean;
  /** The commit the change set became. */
  commit?: string | null;
  discarded?: boolean;
  budget?: BudgetSnapshot | null;
  lane_id?: string | null;
  change_id?: string | null;
  review_round?: number | null;
  rebased?: boolean;
  conflicts?: LaneConflict[];
  provenance_steps?: ProvenanceStep[];
  insights?: SessionInsight[];
  limit_secs?: number;
  checkpoints?: SessionCheckpoint[];
  resumed_from?: string | null;
}

export interface SessionChange {
  path: string;
  kind: "added" | "modified" | "deleted";
  /** Bytes now; 0 when deleted. */
  size: number;
}

export interface SessionDiffFile {
  path: string;
  kind: "added" | "modified" | "deleted";
  size: number;
  binary: boolean;
  truncated: boolean;
  patch: string;
}

export interface SessionDiffResponse {
  session_id: string;
  truncated: boolean;
  files: SessionDiffFile[];
}

export interface WorktableProfileSecret {
  name: string;
  approval: "auto" | "jit" | "unconfigured";
  hosts: string[];
}

export interface WorktableAgentProfile {
  name: string;
  allow_paths: string[];
  deny_paths: string[];
  capabilities: string[];
  allow_secret_use: WorktableProfileSecret[];
  allow_egress_hosts: string[];
}

export interface WorktableBranch {
  name: string;
  head_oid: string;
  subject: string;
  author: string;
  updated_at: string;
  relative_time: string;
  visibility: Visibility;
  readiness: "wip" | "ready";
  is_current: boolean;
  ahead_commits: number;
  private_paths_touched: string[];
  quarantine_paths: string[];
  publish_candidate: boolean;
}

export interface WorktableReviewSummary {
  change_id: string;
  title: string;
  branch: string;
  base_ref: string;
  author: string;
  delegated_agent?: string | null;
  visibility: Visibility;
  readiness: "wip" | "ready";
  quarantine_flagged: boolean;
  quarantine_paths: string[];
  round_count: number;
  comment_count: number;
  verdicts: Record<string, string>;
  created_at: string;
  latest_commit_oid?: string | null;
  session_id?: string | null;
}

export interface WorktableQuarantineItem {
  id: string;
  path: string;
  branch: string;
  change_id?: string | null;
  author: string;
  title: string;
  severity: "high" | "medium";
  reason: string;
}

export interface WorktableTelemetry {
  active_sessions: number;
  pending_approvals: number;
  uncommitted_sessions: number;
  quarantined_count: number;
  ready_to_publish_count: number;
  /** Owner-only: omitted/null for members. */
  bytes_scrubbed_total?: number | null;
  /** Owner-only: omitted/null for members. */
  blocked_count?: number | null;
}

export interface WorktableResponse {
  principal: string;
  agent_profile?: string | null;
  default_branch: string;
  is_owner: boolean;
  branches: WorktableBranch[];
  reviews: WorktableReviewSummary[];
  quarantine_items: WorktableQuarantineItem[];
  /** Owner-only: always [] for members. */
  agent_profiles: WorktableAgentProfile[];
  telemetry: WorktableTelemetry;
}

export type Role = "owner" | "member";

export interface User {
  username: string;
  display_name: string;
  principal: string;
  role: Role;
  totp_enabled: boolean;
  recovery_codes_left: number;
  created_at: string;
}

/** An account as the owner sees it in Settings → Users. */
export interface UserRow {
  username: string;
  display_name: string;
  principal: string;
  role: Role;
  totp_enabled: boolean;
  disabled: boolean;
  created_at: string;
  last_login_at: string | null;
}

export const USERNAME_PATTERN = "[a-z0-9_\\-]{2,32}";

export interface AuthStatus {
  setup_required: boolean;
  authenticated: boolean;
  user: User | null;
}

export interface AuthSession {
  id: string;
  created_at: string;
  last_seen_at: string;
  user_agent: string | null;
  ip: string | null;
  current: boolean;
}

export interface AccessToken {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
}

export interface SshKey {
  id: string;
  name: string;
  key_type: string;
  fingerprint: string;
  created_at: string;
}

export interface TotpEnrollment {
  secret: string;
  otpauth_url: string;
  qr_svg: string;
}

export interface SecurityEvent {
  at: string;
  kind: string;
  /** The account that acted; owners see every account's events. Empty on old events. */
  username?: string;
  ip: string | null;
  user_agent: string | null;
  detail: string | null;
}

/** Lens preset for the real signed-in account (the default "View as"). */
export function selfIdentity(user: User, groups: string[] = []): IdentityPreset {
  return {
    id: "self",
    label: user.principal,
    subtitle: "You • signed in",
    principal: user.principal,
    groups,
    badgeColor: "emerald",
  };
}

const ANONYMOUS_IDENTITY: IdentityPreset = {
  id: "anonymous",
  label: "anonymous",
  subtitle: "Public projection",
  principal: "anonymous",
  groups: [],
  badgeColor: "zinc",
};

/**
 * "View as" choices: yourself, every other directory principal, then anonymous. Each principal is
 * followed by one delegated-agent variant (human ∩ agent_task) per profile the policy declares;
 * the lens menu shows those variants only for the principal currently selected.
 */
export function lensPresets(
  user: User,
  directory: Directory | null,
  agentProfiles: string[] = [],
): IdentityPreset[] {
  const entries = directory?.principals ?? [];
  const humans: IdentityPreset[] = [
    selfIdentity(user, entries.find((p) => p.principal === user.principal)?.groups),
    ...entries
      .filter((p) => p.principal !== user.principal)
      .map(
        (p): IdentityPreset => ({
          id: `p:${p.principal}`,
          label: p.principal,
          subtitle: p.display_name,
          principal: p.principal,
          groups: p.groups,
          badgeColor: "amber",
        }),
      ),
    ANONYMOUS_IDENTITY,
  ];
  return humans.flatMap((h): IdentityPreset[] =>
    h.principal !== "anonymous"
      ? [
          h,
          ...agentProfiles.map(
            (profile): IdentityPreset => ({
              ...h,
              id: `${h.id}:agent:${profile}`,
              label: `${h.principal} ∩ ${profile}`,
              subtitle: "Delegated Agent • human ∩ agent_task",
              agentProfile: profile,
              badgeColor: "indigo",
            }),
          ),
        ]
      : [h],
  );
}

export type SyncDirection = "bidirectional" | "outbound" | "inbound";

export interface GithubCompanionConfig {
  owner: string;
  repo: string;
  full_name: string;
  host: string;
  api_host: string;
  default_branch: string;
  zone: string | null;
  sync_direction: SyncDirection;
  token_configured: boolean;
  token_updated_at?: string | null;
  connected_at: string;
  connected_by: string;
}

export interface GithubSyncState {
  last_canonical_oid?: string | null;
  last_upstream_oid?: string | null;
  mapped_commits: number;
  last_policy_fingerprint?: string | null;
  last_sync_out_at?: string | null;
  last_sync_in_at?: string | null;
  last_sync_summary?: string | null;
}

export interface GithubPrReceipt {
  id: string;
  source_branch: string;
  base_branch: string;
  pr_branch: string;
  pr_number: number;
  pr_url: string;
  pr_title: string;
  public_commit_oid: string;
  published_paths: string[];
  scrubbed_paths_count: number;
  attestation_trailer: string;
  change_id?: string | null;
  created_by: string;
  created_at: string;
}

export interface GithubCompanionStatus {
  connected: boolean;
  config?: GithubCompanionConfig | null;
  sync_state?: GithubSyncState | null;
  receipts: GithubPrReceipt[];
  available_zones: string[];
  enterprise_hosts_allowed: string[];
}

export interface GithubConfigPayload {
  repo: string;
  default_branch?: string;
  zone?: string | null;
  sync_direction?: SyncDirection;
  host?: string;
  api_host?: string;
  token?: string;
}

export interface GithubPrRequest {
  source_branch: string;
  base_branch?: string;
  pr_branch?: string;
  title?: string;
  body?: string;
}

export interface ProjectedFileDiff {
  path: string;
  status: "added" | "modified" | "deleted" | string;
  additions: number;
  deletions: number;
  binary: boolean;
  truncated: boolean;
  patch: string;
}

export interface ScrubbedMetadataSummary {
  commits_squashed: number;
  private_ancestry_stripped: boolean;
  canonical_oids_stripped: boolean;
  copyfrom_history_stripped: boolean;
  source_branch_name_redacted: boolean;
  omitted_paths_count: number;
}

export interface GithubPrPreviewResponse {
  repo: string;
  source_branch: string;
  base_branch: string;
  pr_branch: string;
  zone?: string | null;
  gate_passed: boolean;
  reason?: string | null;
  published_paths: string[];
  scrubbed_paths: string[];
  held_back_reasons: Record<string, string>;
  conflicts: string[];
  blocked: string[];
  diffs: ProjectedFileDiff[];
  diff_truncated: boolean;
  scrubbed_metadata: ScrubbedMetadataSummary;
  clean_commit_message: string;
  pr_title: string;
  pr_body: string;
  attestation_trailer: string;
}

export interface PublishGithubPrResponse {
  receipt: GithubPrReceipt;
  published_paths: string[];
  scrubbed_paths: string[];
}

export interface SyncOutRequest {
  source_branch?: string;
  target_branch?: string;
  zone?: string;
  squash?: boolean;
  summary_message?: string;
  dry_run?: boolean;
}

export interface SyncOutResponse {
  dry_run: boolean;
  up_to_date: boolean;
  zone?: string | null;
  source_branch: string;
  target_branch: string;
  commits_projected: number;
  commits_collapsed: number;
  published_paths: string[];
  scrubbed_paths: string[];
  blocked: string[];
  canonical_tip: string;
  upstream_tip?: string | null;
  attestation_trailer: string;
}

export interface SyncInRequest {
  upstream_ref?: string;
  pr_number?: number;
  target_branch?: string;
  dry_run?: boolean;
}

export interface InboundPolicyViolation {
  commit_oid: string;
  path: string;
  reason: string;
}

export interface SyncInResponse {
  dry_run: boolean;
  up_to_date: boolean;
  zone?: string | null;
  upstream_ref: string;
  target_branch: string;
  commits_imported: number;
  imported_paths: string[];
  preserved_hidden_count: number;
  policy_violations: InboundPolicyViolation[];
  conflicts: string[];
  upstream_tip: string;
  new_canonical_tip?: string | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** Parsed JSON error body when the server sent one (e.g. `{ error, totp_required }`). */
    readonly body: Record<string, unknown> | null,
  ) {
    super(message);
  }
}

/** Human-readable text for inline form errors. */
export function errorText(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403 && typeof err.body?.error !== "string") return "Owner only.";
    if (typeof err.body?.error === "string") return err.body.error;
    if (err.status === 429) return "Too many attempts. Try again later.";
  }
  return err instanceof Error ? err.message : String(err);
}

let unauthorizedListener: (() => void) | null = null;

/** Registers the single handler called when a session-protected call returns 401. Returns an unsubscribe. */
export function onUnauthorized(listener: () => void): () => void {
  unauthorizedListener = listener;
  return () => {
    if (unauthorizedListener === listener) unauthorizedListener = null;
  };
}

export interface Repo {
  name: string;
  description: string;
  is_default: boolean;
  default_branch: string | null;
  created_at: string | null;
  head_oid: string | null;
}

/** Mirrors the server's `valid_branch_name` (`git check-ref-format --branch`). Returns an error or null. */
export function branchNameError(name: string): string | null {
  if (!name) return "Enter a branch name.";
  if (name.startsWith("refs/")) return 'The name can\'t start with "refs/".';
  if (name === "HEAD") return 'The name can\'t be "HEAD".';
  if (name === "@") return 'The name can\'t be "@".';
  if (name.startsWith("-")) return 'The name can\'t start with "-".';
  if (name.startsWith("/") || name.endsWith("/") || name.includes("//")) {
    return 'The name can\'t start or end with "/" or contain "//".';
  }
  if (name.startsWith(".") || name.endsWith(".") || name.includes("..") || name.includes("/.")) {
    return 'The name can\'t start or end with "." or contain ".." or "/.".';
  }
  if (name.includes("@{")) return 'The name can\'t contain "@{".';
  if (name.endsWith(".lock") || name.includes(".lock/")) {
    return 'The name can\'t end with ".lock".';
  }
  if (/[\x00-\x20\x7f~^:?*[\\]/.test(name)) {
    return "The name contains spaces or characters Git forbids in branch names.";
  }
  return null;
}

const RESERVED_PATH_COMPONENTS = [".git", ".premier", ".premier-local"];

/** A new file's path, relative to a folder. The server checks again; returns an error or null. */
export function newFilePathError(path: string): string | null {
  if (!path) return "Enter a file name.";
  if (/^([\\/]|[a-zA-Z]:)/.test(path)) return "Use a path relative to the current folder.";
  if (path.includes("\\")) return 'Separate folders with "/".';
  for (const part of path.split("/")) {
    if (part === "" || part === ".") return 'The path has an empty or "." part.';
    if (part === "..") return 'The path can\'t contain "..".';
    // Trailing dots and spaces are dropped by Windows, so ".git." is ".git".
    if (RESERVED_PATH_COMPONENTS.includes(part.toLowerCase().replace(/[. ]+$/, ""))) {
      return `"${part}" is reserved.`;
    }
  }
  return null;
}

/** Mirrors the server: `[a-z0-9][a-z0-9._-]{0,62}`, not ending `.git` or reserved. Returns an error or null. */
export function repoNameError(name: string): string | null {
  if (!/^[a-z0-9][a-z0-9._-]{0,62}$/.test(name)) {
    return 'Use 1–63 of a–z, 0–9, ".", "-" or "_", starting with a letter or digit.';
  }
  if (name.endsWith(".git")) return 'The name can\'t end in ".git".';
  if (name === "repo" || name === "auth") return 'The names "repo" and "auth" are reserved.';
  return null;
}

/** Server-wide endpoints: never repo-prefixed. Everything else under /v1 is repo-scoped. */
const GLOBAL_PREFIXES = [
  "/health",
  "/v1/auth",
  "/v1/repos",
  "/v1/users",
  "/v1/directory",
  "/v1/settings",
  "/v1/security/offboard",
];

const isGlobalPath = (path: string) =>
  GLOBAL_PREFIXES.some(
    // Boundary match, so "/v1/repos" never swallows the repo-scoped "/v1/repo/tree".
    (p) => path === p || path.startsWith(`${p}/`) || path.startsWith(`${p}?`),
  );

let currentRepo: Repo | null = null;

/** Selects the repository every repo-scoped call, the SSE stream and download links use. */
export function setCurrentRepo(repo: Repo | null): void {
  currentRepo = repo;
}

/** Name used in clone URLs; "repo" only when the repository list couldn't be loaded. */
export const currentRepoName = (): string => currentRepo?.name ?? "repo";

/** Returns true when no non-default repository is selected. */
export const currentRepoIsDefault = (): boolean => currentRepo?.is_default ?? true;

/** Prefixes a repo-scoped path with `/r/{name}`; the default repo and global paths stay bare. */
export function repoPath(path: string): string {
  if (!currentRepo || currentRepo.is_default || isGlobalPath(path)) return path;
  return `/r/${encodeURIComponent(currentRepo.name)}${path}`;
}

async function fetchJsonRaw<T>(path: string, init?: RequestInit): Promise<T> {
  const url = repoPath(path);
  const headers: Record<string, string> = {};
  if (init?.body !== undefined) {
    headers["content-type"] = "application/json";
  }
  if (init?.headers) {
    if (init.headers instanceof Headers) {
      init.headers.forEach((v, k) => {
        headers[k] = v;
      });
    } else if (Array.isArray(init.headers)) {
      for (const [k, v] of init.headers) headers[k] = v;
    } else {
      Object.assign(headers, init.headers);
    }
  }
  const res = await fetch(url, {
    credentials: "same-origin",
    ...init,
    headers,
  });
  if (!res.ok) {
    const text = await res.text();
    let body: Record<string, unknown> | null = null;
    try {
      const parsed: unknown = JSON.parse(text);
      if (parsed && typeof parsed === "object") body = parsed as Record<string, unknown>;
    } catch {
      // non-JSON error body
    }
    // Only a 401 means "session gone"; a 403 (owner-only call) stays signed in and shows inline.
    // A 401 on an auth mutation means "wrong password/code", not "session gone".
    const credentialCheck = url.startsWith("/v1/auth/") && (init?.method ?? "GET") !== "GET";
    if (res.status === 401 && !credentialCheck) unauthorizedListener?.();
    throw new ApiError(`${res.status} ${res.statusText}: ${text}`, res.status, body);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ── Read cache ──────────────────────────────────────────────────────────────
// Short-TTL response cache + in-flight GET dedup so tab switches and revisited files/commits are
// instant. Any mutation (or `invalidateApiCache()`, called from SSE handlers) clears everything.
// shortcut: responses are shared by reference, so callers must not mutate them; no size cap
// (entries expire on read and the whole map is dropped on mutation).
const MUTABLE_TTL_MS = 8_000;
const IMMUTABLE_TTL_MS = 60_000;
const SHA40 = /^[0-9a-f]{40}$/i;
const CACHEABLE_GET =
  /^\/v1\/(commits|branches|reviews|worktable|hygiene\/insights|env\/dashboard|directory|lanes|approvals\/suggestions|mcp\/gateways|policy\/summary|repo\/(tree|file|search|blame))$/;
// POSTs that only read; they must not wipe the cache.
const READ_ONLY_POST =
  /^\/v1\/(access\/(explain|diff|scan)|policy\/(diff|propose|explain-secrets)|overlays\/check|branches\/squash-preview|approvals\/suggestions\/[^/]+\/preview)$/;

const responseCache = new Map<string, { at: number; ttl: number; value: unknown }>();
const inflightGets = new Map<string, Promise<unknown>>();
let cacheEpoch = 0;

/** Drops every cached read; the next GET goes to the network. */
export function invalidateApiCache(): void {
  cacheEpoch += 1;
  responseCache.clear();
  inflightGets.clear();
}

function cacheTtlMs(path: string): number {
  const [pathname, qs = ""] = path.split("?");
  if (/^\/v1\/commits\/[0-9a-f]{40}$/i.test(pathname)) return IMMUTABLE_TTL_MS;
  if (!CACHEABLE_GET.test(pathname)) return 0;
  if (pathname.startsWith("/v1/repo/")) {
    const ref = new URLSearchParams(qs).get("ref_name");
    if (ref && SHA40.test(ref)) return IMMUTABLE_TTL_MS;
  }
  return MUTABLE_TTL_MS;
}

function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const [pathname] = path.split("?");
  if (method !== "GET") {
    if (READ_ONLY_POST.test(pathname)) return fetchJsonRaw<T>(path, init);
    // Clear on start and on finish, so reads that raced the write can't repopulate stale data.
    invalidateApiCache();
    return fetchJsonRaw<T>(path, init).finally(invalidateApiCache);
  }
  const ttl = cacheTtlMs(path);
  if (ttl === 0) return fetchJsonRaw<T>(path, init);
  const key = repoPath(path);
  const hit = responseCache.get(key);
  if (hit && Date.now() - hit.at < hit.ttl) return Promise.resolve(hit.value as T);
  const pending = inflightGets.get(key);
  if (pending) return pending as Promise<T>;
  const epoch = cacheEpoch;
  const req = fetchJsonRaw<T>(path, init)
    .then((value) => {
      if (epoch === cacheEpoch) responseCache.set(key, { at: Date.now(), ttl, value });
      return value;
    })
    .finally(() => {
      if (inflightGets.get(key) === req) inflightGets.delete(key);
    });
  inflightGets.set(key, req);
  return req;
}

const post = (body?: unknown): RequestInit => ({
  method: "POST",
  body: body === undefined ? undefined : JSON.stringify(body),
});

/** Query string for a "View as" read; the server resolves groups from the directory. */
function lensQuery(
  identity: IdentityPreset,
  extra: Record<string, string | undefined> = {},
): string {
  // Undefined entries are left out, so an unselected ref falls back to the server's default.
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(extra)) if (v !== undefined) params.set(k, v);
  params.set("principal", identity.principal);
  if (identity.agentProfile) params.set("agent_profile", identity.agentProfile);
  return params.toString();
}

/** `?a=b` from the defined, non-empty entries only. */
function query(params: Record<string, string | number | undefined>): string {
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") out.set(k, String(v));
  }
  const qs = out.toString();
  return qs ? `?${qs}` : "";
}

const directoryPrincipalUrl = (principal: string) =>
  `/v1/directory/principals/${encodeURIComponent(principal)}`;

export const authApi = {
  status: () => fetchJson<AuthStatus>("/v1/auth/status"),
  setup: (payload: { username: string; password: string; display_name?: string }) =>
    fetchJson<AuthStatus>("/v1/auth/setup", post(payload)),
  login: (payload: { username: string; password: string; totp_code?: string }) =>
    fetchJson<AuthStatus>("/v1/auth/login", post(payload)),
  logout: () => fetchJson<void>("/v1/auth/logout", post()),
  changePassword: (current_password: string, new_password: string) =>
    fetchJson<void>("/v1/auth/password", post({ current_password, new_password })),
  updateProfile: (display_name: string) =>
    fetchJson<User>("/v1/auth/profile", {
      method: "PATCH",
      body: JSON.stringify({ display_name }),
    }),
  sessions: () => fetchJson<AuthSession[]>("/v1/auth/sessions"),
  revokeSession: (id: string) =>
    fetchJson<void>(`/v1/auth/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),
  revokeOtherSessions: () => fetchJson<void>("/v1/auth/sessions/revoke-others", post()),
  tokens: () => fetchJson<AccessToken[]>("/v1/auth/tokens"),
  createToken: (name: string, expires_in_days?: number) =>
    fetchJson<AccessToken & { token: string }>("/v1/auth/tokens", post({ name, expires_in_days })),
  revokeToken: (id: string) =>
    fetchJson<void>(`/v1/auth/tokens/${encodeURIComponent(id)}`, { method: "DELETE" }),
  sshKeys: () => fetchJson<SshKey[]>("/v1/auth/ssh-keys"),
  addSshKey: (name: string, public_key: string) =>
    fetchJson<SshKey>("/v1/auth/ssh-keys", post({ name, public_key })),
  revokeSshKey: (id: string) =>
    fetchJson<void>(`/v1/auth/ssh-keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
  totpBegin: () => fetchJson<TotpEnrollment>("/v1/auth/totp/begin", post()),
  totpEnable: (code: string) =>
    fetchJson<{ recovery_codes: string[] }>("/v1/auth/totp/enable", post({ code })),
  newRecoveryCodes: (password: string) =>
    fetchJson<{ recovery_codes: string[] }>("/v1/auth/totp/recovery-codes", post({ password })),
  totpDisable: (password: string) => fetchJson<void>("/v1/auth/totp/disable", post({ password })),
  events: () => fetchJson<SecurityEvent[]>("/v1/auth/events"),
};

const repoUrl = (name: string) => `/v1/repos/${encodeURIComponent(name)}`;

export const api = {
  health: () => fetchJson<HealthResponse>("/health"),
  repos: () => fetchJson<Repo[]>("/v1/repos"),
  /** With `import_url` the server clones first, so this can take minutes. */
  createRepo: (payload: { name: string; description?: string; import_url?: string }) =>
    fetchJson<Repo & { imported_policy?: boolean }>("/v1/repos", post(payload)),
  updateRepo: (name: string, description: string) =>
    fetchJson<Repo>(repoUrl(name), { method: "PATCH", body: JSON.stringify({ description }) }),
  deleteRepo: (name: string) =>
    fetchJson<void>(repoUrl(name), { method: "DELETE", body: JSON.stringify({ confirm: name }) }),
  policySummary: () => fetchJson<PolicySummaryResponse>("/v1/policy/summary"),
  // `refName` undefined = the repo's checked-out branch (the server's default).
  repoTree: (identity: IdentityPreset, xray: boolean, refName?: string) =>
    fetchJson<RepoTreeResponse>(
      `/v1/repo/tree?${lensQuery(identity, { ref_name: refName, xray: String(xray) })}`,
    ),
  repoFile: (identity: IdentityPreset, path: string, refName?: string) =>
    fetchJson<RepoFileResponse>(
      `/v1/repo/file?${lensQuery(identity, { ref_name: refName, path, max_bytes: "524288" })}`,
    ),
  explain: (identity: IdentityPreset, path: string, refName?: string) =>
    fetchJson<ExplainDecision>("/v1/access/explain", {
      method: "POST",
      body: JSON.stringify({
        principal: identity.principal,
        agent_profile: identity.agentProfile ?? null,
        path,
        ref_name: refName,
      }),
    }),
  accessDiff: (payload: {
    base_toml: string;
    head_toml: string;
    server_toml?: string;
    principals?: string[];
    paths?: string[];
    ref_name?: string;
    include_agent_profiles?: boolean;
    secret_probes?: SecretProbeInput[];
    changed_files: { path: string; content?: string }[];
  }) =>
    fetchJson<AccessImpactDiff>("/v1/access/diff", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  accessScan: (payload: {
    branch?: string;
    target_branch?: string;
    message?: string;
    files?: { path: string; content: string }[];
  }) => fetchJson<DeclassificationReport>("/v1/access/scan", post(payload)),
  quarantineOverview: () => fetchJson<QuarantineOverviewResponse>("/v1/quarantine"),
  quarantineApprove: (payload: {
    pending_id?: string;
    path?: string;
    sha256?: string;
    reason: string;
    acknowledge_diff: boolean;
    apply_commit?: boolean;
  }) =>
    fetchJson<{ ok: boolean; path: string; sha256: string; commit?: string | null }>(
      "/v1/quarantine/approve",
      post(payload),
    ),
  quarantineReject: (payload: { pending_id?: string; path?: string; reason: string }) =>
    fetchJson<{ ok: boolean }>("/v1/quarantine/reject", post(payload)),
  envDashboard: (identity?: IdentityPreset) =>
    fetchJson<SchemaDashboardResponse>(
      identity ? `/v1/env/dashboard?${lensQuery(identity)}` : "/v1/env/dashboard",
    ),
  policyDiff: (payload: {
    base_toml: string;
    head_toml: string;
    server_toml?: string;
    principals?: string[];
    paths?: string[];
    ref_name?: string;
    include_agent_profiles?: boolean;
    secret_probes?: SecretProbeInput[];
    changed_files: { path: string; content?: string }[];
  }) =>
    fetchJson<AccessImpactDiff>("/v1/policy/diff", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  proposePolicyIntent: (payload: {
    intent: PolicyIntent;
    base_toml?: string;
    ref_name?: string;
  }) =>
    fetchJson<ProposePolicyIntentResponse>("/v1/policy/propose", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  explainSecrets: (identity: IdentityPreset, refName?: string) =>
    fetchJson<ExplainSecretsResponse>("/v1/policy/explain-secrets", {
      method: "POST",
      body: JSON.stringify({
        principal: identity.principal,
        agent_profile: identity.agentProfile ?? null,
        ref_name: refName,
      }),
    }),
  auditList: (
    params: { limit?: number; q?: string; principal?: string; decision?: AuditDecision } = {},
  ) => fetchJson<AuditEvent[]>(`/v1/audit${query(params)}`),
  directory: () => fetchJson<Directory>("/v1/directory"),
  saveDirectoryPrincipal: (principal: string, display_name: string, groups: string[]) =>
    fetchJson<Directory>(directoryPrincipalUrl(principal), {
      method: "PUT",
      body: JSON.stringify({ display_name, groups }),
    }),
  deleteDirectoryPrincipal: (principal: string) =>
    fetchJson<Directory>(directoryPrincipalUrl(principal), { method: "DELETE" }),
  users: () => fetchJson<UserRow[]>("/v1/users"),
  createUser: (payload: {
    username: string;
    password: string;
    display_name?: string;
    role?: Role;
  }) => fetchJson<UserRow>("/v1/users", post(payload)),
  updateUser: (
    username: string,
    patch: { display_name?: string; role?: Role; disabled?: boolean; password?: string },
  ) =>
    fetchJson<UserRow>(`/v1/users/${encodeURIComponent(username)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  deleteUser: (username: string) =>
    fetchJson<void>(`/v1/users/${encodeURIComponent(username)}`, { method: "DELETE" }),
  settings: () => fetchJson<WorkspaceSettings>("/v1/settings"),
  updateSettings: (settings: WorkspaceSettings) =>
    fetchJson<WorkspaceSettings>("/v1/settings", {
      method: "PATCH",
      body: JSON.stringify(settings),
    }),
  approvalsList: () => fetchJson<PendingApproval[]>("/v1/approvals"),
  decideApproval: (
    id: string,
    approved: boolean,
    ttlSecs?: number,
    options?: ApprovalDecisionOptions,
  ) =>
    fetchJson<PendingApproval>(`/v1/approvals/${encodeURIComponent(id)}/decide`, {
      method: "POST",
      body: JSON.stringify({ approved, ttl_secs: ttlSecs, ...options }),
    }),
  approvalSuggestions: () => fetchJson<PolicySuggestion[]>("/v1/approvals/suggestions"),
  previewApprovalSuggestion: (id: string) =>
    fetchJson<PolicySuggestionPreview>(
      `/v1/approvals/suggestions/${encodeURIComponent(id)}/preview`,
      post(),
    ),
  applyApprovalSuggestion: (id: string) =>
    fetchJson<ApplySuggestionResponse>(
      `/v1/approvals/suggestions/${encodeURIComponent(id)}/apply`,
      post(),
    ),
  dismissApprovalSuggestion: (id: string) =>
    fetchJson<{ ok: boolean }>(
      `/v1/approvals/suggestions/${encodeURIComponent(id)}/dismiss`,
      post(),
    ),
  overlays: (principal?: string) =>
    fetchJson<OverlayManifest>(`/v1/overlays${query({ principal })}`),
  checkOverlays: (paths: string[]) =>
    fetchJson<OverlayCheckResponse>("/v1/overlays/check", {
      method: "POST",
      body: JSON.stringify({ paths }),
    }),
  branches: () => fetchJson<BranchRecord[]>("/v1/branches"),
  updateBranchVisibility: (branch: string, visibility: Visibility, readiness: "wip" | "ready") =>
    fetchJson<{ ok: boolean }>("/v1/branches/visibility", {
      method: "POST",
      body: JSON.stringify({ branch, visibility, readiness }),
    }),
  /** `targetBranch` undefined = the repo's default branch. */
  squashPreview: (branch: string, targetBranch?: string, summaryMessage?: string) =>
    fetchJson<SquashPreviewResponse>("/v1/branches/squash-preview", {
      method: "POST",
      body: JSON.stringify({
        branch,
        target_branch: targetBranch,
        summary_message: summaryMessage,
      }),
    }),
  reviews: (identity: IdentityPreset) =>
    fetchJson<ChangeReviewRecord[]>(`/v1/reviews?${lensQuery(identity)}`),
  worktable: (identity: IdentityPreset) =>
    fetchJson<WorktableResponse>(`/v1/worktable?${lensQuery(identity)}`),
  commits: (
    identity: IdentityPreset,
    params: { ref?: string; limit?: number; skip?: number } = {},
  ) =>
    fetchJson<GitCommitSummary[]>(
      `/v1/commits${query({ ...params, principal: identity.principal, agent_profile: identity.agentProfile })}`,
    ),
  commitDiff: (oid: string, identity: IdentityPreset) =>
    fetchJson<GitCommitDiffResponse>(
      `/v1/commits/${encodeURIComponent(oid)}?${lensQuery(identity)}`,
    ),
  repoSearch: (identity: IdentityPreset, q: string, refName?: string) =>
    fetchJson<RepoSearchResponse>(
      `/v1/repo/search?${lensQuery(identity, { q, ref_name: refName })}`,
    ),
  repoBlame: (identity: IdentityPreset, path: string, refName?: string) =>
    fetchJson<RepoBlameResponse>(
      `/v1/repo/blame?${lensQuery(identity, { path, ref_name: refName })}`,
    ),
  /** The save becomes a commit on `refName`; `message` undefined = the server's default. */
  writeRepoFile: (
    identity: IdentityPreset,
    path: string,
    content: string,
    refName?: string,
    message?: string,
    expectedTip?: string,
  ) =>
    fetchJson<WriteRepoFileResponse>("/v1/repo/file", {
      method: "PUT",
      body: JSON.stringify({
        path,
        content,
        message,
        principal: identity.principal,
        agent_profile: identity.agentProfile ?? null,
        ref_name: refName,
        expected_tip: expectedTip,
      }),
    }),
  /** Deletes a file in one commit on `refName`; `message` undefined = the server's default. */
  deleteRepoFile: (
    identity: IdentityPreset,
    path: string,
    refName?: string,
    message?: string,
  ) =>
    fetchJson<WriteRepoFileResponse>(
      `/v1/repo/file${query({
        path,
        ref_name: refName,
        message,
        principal: identity.principal,
        agent_profile: identity.agentProfile,
      })}`,
      {
        method: "DELETE",
        body: JSON.stringify({
          path,
          content: "",
          message,
          principal: identity.principal,
          agent_profile: identity.agentProfile ?? null,
          ref_name: refName,
        }),
      },
    ),
  updateRepoPolicy: (toml: string, principal?: string, expectedBaseSha256?: string) =>
    fetchJson<UpdateRepoPolicyResponse>("/v1/policy/repo", {
      method: "PUT",
      body: JSON.stringify({
        toml,
        principal,
        expected_base_sha256: expectedBaseSha256,
      }),
    }),
  /** Members pass no `visibility`: the server makes the branch private to them. */
  createBranch: (
    name: string,
    visibility: Visibility | undefined,
    fromRef?: string,
    readiness: "wip" | "ready" = "wip",
  ) =>
    fetchJson<CreateBranchResponse>("/v1/branches/create", {
      method: "POST",
      body: JSON.stringify({ name, from_ref: fromRef, visibility, readiness }),
    }),
  deleteBranch: (name: string) =>
    fetchJson<{ ok: boolean; deleted: string }>(
      `/v1/branches/${name.split("/").map(encodeURIComponent).join("/")}`,
      { method: "DELETE" },
    ),
  /** A 409 carries `{ error, conflicts, hidden_conflicts, blocked, hidden_blocked, declassification_report }` in `ApiError.body`. */
  publishBranch: (
    sourceBranch: string,
    targetBranch?: string,
    summaryMessage?: string,
    expected?: {
      expected_source_oid?: string;
      expected_target_oid?: string;
      /** Airlock ceremony aliases for the CAS heads. */
      sourceOid?: string | null;
      targetOid?: string | null;
    },
    override?: { override_reason: string; override_ack_digest: string },
  ) =>
    fetchJson<PublishBranchResponse>("/v1/branches/publish", {
      method: "POST",
      body: JSON.stringify({
        source_branch: sourceBranch,
        target_branch: targetBranch,
        summary_message: summaryMessage || null,
        expected_source_oid: expected?.expected_source_oid ?? (expected?.sourceOid || undefined),
        expected_target_oid: expected?.expected_target_oid ?? (expected?.targetOid || undefined),
        ...(override ?? {}),
      }),
    }),
  createReview: (payload: {
    title: string;
    branch: string;
    base_ref?: string;
    author?: string;
    delegated_agent?: string | null;
    session_id?: string | null;
    prompt_summary?: string | null;
  }) =>
    fetchJson<StoredReview>("/v1/reviews", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  addReviewComment: (
    changeId: string,
    payload: {
      path: string;
      line?: number | null;
      side?: "old" | "new" | null;
      body: string;
      author: string;
      kind?: "comment" | "steer";
      target_agent?: string | null;
      steer_session_id?: string | null;
    },
  ) =>
    fetchJson<ReviewComment>(`/v1/reviews/${encodeURIComponent(changeId)}/comments`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  setReviewVerdict: (changeId: string, round: number, verdict: string, principal: string) =>
    fetchJson<{ ok: boolean }>(`/v1/reviews/${encodeURIComponent(changeId)}/verdict`, {
      method: "POST",
      body: JSON.stringify({ round, verdict, principal }),
    }),
  secretsStatus: () => fetchJson<SecretStatusResponse>("/v1/secrets/status"),
  setSecret: (key: string, value: string, env = "dev", principal?: string) =>
    fetchJson<SecretMetaEntry>("/v1/secrets/set", {
      method: "POST",
      body: JSON.stringify({ key, value, env, principal }),
    }),
  deleteSecret: (key: string, env = "dev", principal?: string) =>
    fetchJson<{ ok: boolean; revoked: string }>(
      `/v1/secrets/${encodeURIComponent(key)}${query({ env, principal })}`,
      { method: "DELETE" },
    ),
  mountOverlay: (payload: {
    path: string;
    scope: string;
    encrypted: boolean;
    create_file: boolean;
    initial_content?: string;
    principal?: string;
  }) =>
    fetchJson<OverlayManifest>("/v1/overlays/mount", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  unmountOverlay: (path: string, principal?: string) =>
    fetchJson<OverlayManifest>("/v1/overlays/unmount", {
      method: "POST",
      body: JSON.stringify({ path, principal }),
    }),
  listSessions: () => fetchJson<AgentSessionRecord[]>("/v1/agents/sessions"),
  spawnSession: (payload: {
    command: string;
    principal: string;
    agent_profile?: string;
    env?: string;
    /** Time limit; the server ends the session when it is reached. */
    max_secs?: number;
    /** Branch the private workspace is taken from; undefined = the repo's default branch. */
    branch?: string;
    lane_id?: string;
    parent_lane_id?: string;
    change_id?: string;
  }) =>
    fetchJson<AgentSessionRecord>("/v1/agents/sessions", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  sessionDiff: (id: string) =>
    fetchJson<SessionDiffResponse>(`/v1/agents/sessions/${encodeURIComponent(id)}/diff`),
  stopSession: (id: string) =>
    fetchJson<AgentSessionRecord>(`/v1/agents/sessions/${encodeURIComponent(id)}/stop`, post()),
  commitSession: (
    id: string,
    message?: string,
    options?: {
      branch?: string;
      new_branch?: string;
      visibility?: Visibility;
      auto_rebase?: boolean;
      lane_id?: string;
      change_id?: string;
    },
  ) =>
    fetchJson<CommitSessionResponse>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/commit`,
      post({ message, ...options }),
    ),
  sessionProvenance: (sessionId: string) =>
    fetchJson<{
      session_id: string;
      command: string;
      principal: string;
      agent_profile: string;
      steps: ProvenanceStep[];
    }>(`/v1/agents/sessions/${encodeURIComponent(sessionId)}/provenance`),
  listLanes: () => fetchJson<AgentLane[]>("/v1/lanes"),
  getLane: (laneId: string) => fetchJson<AgentLane>(`/v1/lanes/${encodeURIComponent(laneId)}`),
  createLane: (payload: {
    lane_id?: string;
    base_branch?: string;
    parent_lane_id?: string;
    change_id?: string;
    agent_profile?: string;
    visibility?: Visibility;
  }) => fetchJson<AgentLane>("/v1/lanes", post(payload)),
  rebaseLane: (laneId: string, options?: { onto_ref?: string; cascade?: boolean }) =>
    fetchJson<LaneRebaseResponse>(
      `/v1/lanes/${encodeURIComponent(laneId)}/rebase`,
      post(options ?? {}),
    ),
  resolveLane: (
    laneId: string,
    payload: {
      resolutions: {
        path: string;
        content: string | null;
        mode?: string;
        strategy?: "ours" | "theirs" | "delete" | "custom";
      }[];
      apply_to_branch?: boolean;
      message?: string;
    },
  ) =>
    fetchJson<LaneResolveResponse>(
      `/v1/lanes/${encodeURIComponent(laneId)}/resolve`,
      post(payload),
    ),
  deleteLane: (laneId: string) =>
    fetchJson<{ ok: boolean; deleted: string }>(`/v1/lanes/${encodeURIComponent(laneId)}`, {
      method: "DELETE",
    }),
  reviewInterdiff: (
    changeId: string,
    identity: IdentityPreset,
    fromRound?: number,
    toRound?: number,
  ) =>
    fetchJson<ReviewInterdiffResponse>(
      `/v1/reviews/${encodeURIComponent(changeId)}/interdiff?${lensQuery(identity, {
        from_round: fromRound !== undefined ? String(fromRound) : undefined,
        to_round: toRound !== undefined ? String(toRound) : undefined,
      })}`,
    ),
  steerReview: (changeId: string, payload: SteerReviewRequest) =>
    fetchJson<SteerReviewResponse>(
      `/v1/reviews/${encodeURIComponent(changeId)}/steer`,
      post(payload),
    ),
  discardSession: (id: string) =>
    fetchJson<AgentSessionRecord>(`/v1/agents/sessions/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  mcpGateways: (identity: IdentityPreset, refName?: string) =>
    fetchJson<McpGatewaysResponse>(
      `/v1/mcp/gateways?${lensQuery(identity, { ref_name: refName })}`,
    ),
  mcpExplain: (payload: {
    principal: string;
    agent_profile?: string | null;
    server: string;
    tool: string;
    arguments?: Record<string, unknown>;
    ref_name?: string;
  }) => fetchJson<McpExplainResponse>("/v1/mcp/explain", post(payload)),
  mcpAlerts: () => fetchJson<McpDriftAlert[]>("/v1/mcp/alerts"),
  approveMcpAlert: (id: string) =>
    fetchJson<McpDriftAlert>(`/v1/mcp/alerts/${encodeURIComponent(id)}/approve`, post()),
  dismissMcpAlert: (id: string, keepQuarantined = true) =>
    fetchJson<McpDriftAlert>(
      `/v1/mcp/alerts/${encodeURIComponent(id)}/dismiss`,
      post({ keep_quarantined: keepQuarantined }),
    ),
  raiseSessionBudget: (id: string, limits: AutonomyBudget, resume = true) =>
    fetchJson<AgentSessionRecord>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/budget`,
      post({ limits, resume }),
    ),
  kmsStatus: () => fetchJson<KmsStatus>("/v1/secrets/kms/status"),
  rotateDek: () =>
    fetchJson<{ ok: boolean; dek_version: number; status: KmsStatus }>(
      "/v1/secrets/kms/rotate-dek",
      post({}),
    ),
  migrateToEnvelope: () =>
    fetchJson<{
      ok: boolean;
      migrated_entries: number;
      already_migrated: boolean;
      status: KmsStatus;
    }>("/v1/secrets/kms/migrate", post({})),
  rotateSecret: (
    key: string,
    payload?: { env?: string; reason?: string; new_value?: string },
  ) =>
    fetchJson<RotationReceipt>(
      `/v1/secrets/${encodeURIComponent(key)}/rotate`,
      post(payload ?? {}),
    ),
  rotationReceipts: () => fetchJson<RotationReceipt[]>("/v1/secrets/rotations"),
  oidcDiscovery: () => fetchJson<OidcDiscoveryDocument>("/v1/oidc/discovery"),
  mintOidcToken: (payload: MintOidcTokenRequest) =>
    fetchJson<IssuedWorkloadToken>("/v1/oidc/token", post(payload)),
  verifyOidcToken: (token: string, audience: string) =>
    fetchJson<VerifyOidcResponse>("/v1/oidc/verify", post({ token, audience })),
  offboardPrincipal: (payload: OffboardRequest) =>
    fetchJson<OffboardReceipt>("/v1/security/offboard", post(payload)),
  offboardReceipts: () => fetchJson<OffboardReceipt[]>("/v1/security/offboard/receipts"),
  githubStatus: () => fetchJson<GithubCompanionStatus>("/v1/github/status"),
  githubConfigure: (payload: GithubConfigPayload) =>
    fetchJson<GithubCompanionStatus>("/v1/github/config", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  githubDisconnect: () => fetchJson<{ ok: boolean }>("/v1/github/config", { method: "DELETE" }),
  /** A 409 carries `{ error, conflicts, blocked }` in `ApiError.body`. */
  githubPreviewPr: (payload: GithubPrRequest) =>
    fetchJson<GithubPrPreviewResponse>("/v1/github/pr/preview", post(payload)),
  githubPublishPr: (payload: GithubPrRequest & { draft?: boolean; change_id?: string }) =>
    fetchJson<PublishGithubPrResponse>("/v1/github/pr/publish", post(payload)),
  githubSyncOut: (payload: SyncOutRequest) =>
    fetchJson<SyncOutResponse>("/v1/github/sync/out", post(payload)),
  githubSyncIn: (payload: SyncInRequest) =>
    fetchJson<SyncInResponse>("/v1/github/sync/in", post(payload)),
  hygieneInsights: (refName?: string, includeDismissed = false) =>
    fetchJson<HygieneInsightsResponse>(
      `/v1/hygiene/insights${query({
        ref_name: refName,
        include_dismissed: includeDismissed ? "true" : "false",
      })}`,
    ),
  dismissHygieneInsight: (id: string) =>
    fetchJson<{ ok: boolean; id: string; dismissed_at: string }>(
      "/v1/hygiene/dismiss",
      post({ id }),
    ),
  restoreHygieneInsight: (id: string) =>
    fetchJson<{ ok: boolean; id: string }>("/v1/hygiene/restore", post({ id })),
  pauseSession: (id: string) =>
    fetchJson<AgentSessionRecord>(`/v1/agents/sessions/${encodeURIComponent(id)}/pause`, post()),
  sessionWorkspaceFiles: (id: string) =>
    fetchJson<SessionWorkspaceFilesResponse>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/workspace/files`,
    ),
  sessionWorkspaceFile: (id: string, path: string) =>
    fetchJson<SessionWorkspaceFileResponse>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/workspace/file?path=${encodeURIComponent(path)}`,
    ),
  writeSessionWorkspaceFile: (id: string, path: string, content: string) =>
    fetchJson<SessionWorkspaceWriteResponse>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/workspace/file`,
      {
        method: "PUT",
        body: JSON.stringify({ path, content }),
      },
    ),
  checkpointSession: (id: string, label?: string) =>
    fetchJson<SessionCheckpointResponse>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/checkpoint`,
      post({ label }),
    ),
  resumeSession: (id: string, command: string, maxSecs?: number) =>
    fetchJson<AgentSessionRecord>(
      `/v1/agents/sessions/${encodeURIComponent(id)}/resume`,
      post({ command, max_secs: maxSecs }),
    ),
  traces: (identity: IdentityPreset, refName?: string) =>
    fetchJson<TraceSession[]>(`/v1/traces?${lensQuery(identity, { ref_name: refName })}`),
  blameTraces: (q: string, identity: IdentityPreset, refName?: string) =>
    fetchJson<TraceSession[]>(
      `/v1/traces/blame?${lensQuery(identity, { q, ref_name: refName })}`,
    ),
  ingestTrace: (payload: Record<string, unknown>) =>
    fetchJson<TraceIngestResponse>("/v1/traces/ingest", post(payload)),
  seedSampleTraces: (identity: IdentityPreset, refName?: string) =>
    fetchJson<TraceSession[]>(
      `/v1/traces/sample?${lensQuery(identity, { ref_name: refName })}`,
      post(),
    ),
  deleteTrace: (sessionId: string) =>
    fetchJson<{ ok: boolean; deleted: boolean; session_id: string }>(
      `/v1/traces/${encodeURIComponent(sessionId)}`,
      { method: "DELETE" },
    ),
};

export function getServerOrigin(): string {
  if (typeof window === "undefined") return "http://127.0.0.1:7420";
  if (window.location.port === "5173") return "http://127.0.0.1:7420";
  return window.location.origin;
}

/** Git remotes for a repo (defaults to the current repo): authenticated (as `username`) and the anonymous projection. */
export function cloneUrls(username: string, repoName?: string): { auth: string; anon: string } {
  const origin = new URL(getServerOrigin());
  const name = encodeURIComponent(repoName ?? currentRepoName());
  return {
    auth: `${origin.protocol}//${encodeURIComponent(username)}@${origin.host}/git/auth/${name}.git`,
    anon: `${origin.origin}/git/${name}.git`,
  };
}

export function capMaskToNames(mask: number): string[] {
  const out: string[] = [];
  if (mask & 0b00001) out.push("traverse");
  if (mask & 0b00010) out.push("list");
  if (mask & 0b00100) out.push("read");
  if (mask & 0b01000) out.push("write");
  if (mask & 0b10000) out.push("use");
  return out;
}
