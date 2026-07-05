export type Verdict =
  | "trusted"
  | "low_concern"
  | "moderate_risk"
  | "suspicious"
  | "known_malicious"
  | "unknown";

export type Theme = 'light' | 'dark' | 'system';

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
}

export interface ProfileInstall {
  profile_id: string;
  profile_name: string;
  browser_channel: string;
  browser_family: string;
  enabled_state: string;
  install_source: string;
  version: string;
  manifest_path: string;
}

export interface SuspiciousSignal {
  code: string;
  title: string;
  severity: number;
  detail: string;
  evidence: string[];
}

export interface IntelMatch {
  extension_id: string;
  label: string;
  source: string;
  source_url: string;
  confidence: string;
  detail: string;
  category: string;
}

export interface ReputationDetails {
  extension_id: string;
  user_count: number;
  user_count_display: string;
  star_rating: number;
  review_count: number;
  last_updated: string;
  developer_name: string;
  is_featured: boolean;
  is_established_publisher: boolean;
  reputation_score: number;
  lookup_status: string;
}

export interface Recommendation {
  name: string;
  extension_id: string;
  publisher: string;
  category: string;
  users: string;
  rating: number;
  reason: string;
  install_url: string;
}

// v4 Phase 1 types

export interface CollusionEdge {
  source_id: string;
  source_name: string;
  target_id: string;
  target_name: string;
  risk_type: string;
  detail: string;
  severity: string;
}

export interface DomainIntelResult {
  domain: string;
  source: string;
  isMalicious: boolean;
  confidence: number;
  detail: string;
  lastChecked: string;
}

export interface DeltaResult {
  extensionId: string;
  oldVersion: string;
  newVersion: string;
  structuralChanges: string[];
  riskAssessment: string;
  newEvalCountDelta: number;
  newObfuscatedDelta: number;
  severity: string;
}

export interface ExtensionFinding {
  id: string;
  name: string;
  version: string;
  description: string;
  manifestVersion: number;
  profiles: ProfileInstall[];
  enabledState: string;
  installSource: string;
  reachScore: number;
  anomalyScore: number;
  verdict: Verdict;
  subVerdict?: string | null;
  storeStatus: string;
  permissions: string[];
  optionalPermissions: string[];
  hostPermissions: string[];
  optionalHostPermissions: string[];
  contentScriptMatches: string[];
  suspiciousSignals: SuspiciousSignal[];
  intelMatches: IntelMatch[];
  aiSummary: string | null;
  evidenceTimeline: string[];
  packageRoot?: string;
  homepageUrl?: string;
  author?: string;
  // v3 fields
  category?: string;
  reputationScore?: number;
  reputationDetails?: ReputationDetails;
  adjustedAnomalyScore?: number;
  recommendations?: Recommendation[];
  // v4 Phase 1 fields
  collusionEdges?: CollusionEdge[];
  domainIntel?: DomainIntelResult[];
  versionDelta?: DeltaResult | null;
  intentClassification?: {
    category: string;
    is_deceptive: boolean;
    reason: string;
  };
  attackSimulation?: string;
  deobfuscatedPayload?: string;
}

export interface ScanSummary {
  totalExtensions: number;
  verdictDistribution: Record<string, number>;
}

export interface ScanRecord {
  scanId: string;
  label: string;
  createdAt: string;
  status: string;
  source: string;
  options: {
    enableLiveChecks: boolean;
    enableAi: boolean;
  };
  summary: ScanSummary;
  extensions?: ExtensionFinding[];
}
