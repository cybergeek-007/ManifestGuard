export type Verdict =
  | "trusted"
  | "low_concern"
  | "powerful_but_expected"
  | "moderate_risk"
  | "suspicious"
  | "known_malicious"
  | "removed_or_unavailable"
  | "disabled_by_chrome"
  | "unknown";

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

export interface ExtensionFinding {
  id: string;
  name: string;
  version: string;
  description: string;
  manifestVersion: number;
  profiles: ProfileInstall[];
  enabledState: string;
  installSource: string;
  powerScore: number;
  suspicionScore: number;
  verdict: Verdict;
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
  adjustedSuspicionScore?: number;
  recommendations?: Recommendation[];
}

export interface ScanSummary {
  totalExtensions: number;
  verdictDistribution: Record<string, number>;
  profilesScanned: string[];
  channelsScanned: string[];
}

export interface ScanRecord {
  scanId: string;
  label: string;
  createdAt: string;
  status: string;
  source: string;
  options: {
    profiles: string[];
    channels: string[];
    enableLiveChecks: boolean;
    enableAi: boolean;
    roots?: string[];
  };
  summary: ScanSummary;
  extensions?: ExtensionFinding[];
}
