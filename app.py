"""
ManifestGuard - AI-Powered Local Chrome Extension Auditor
A beginner-friendly tool to audit Chrome extensions for privacy risks.
"""

import os
import json
import platform
import streamlit as st
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from openai import OpenAI

# ============== CONFIGURATION ==============

# Risk scoring weights
RISK_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5
}

# Permission risk classifications
PERMISSION_RISKS = {
    # CRITICAL - Can completely compromise privacy/security
    "all_urls": "CRITICAL",
    "<all_urls>": "CRITICAL",
    "webRequestBlocking": "CRITICAL",
    "debugger": "CRITICAL",
    "proxy": "CRITICAL",
    "background": "CRITICAL",
    
    # HIGH - Significant data access
    "history": "HIGH",
    "bookmarks": "HIGH",
    "cookies": "HIGH",
    "storage": "HIGH",
    "unlimitedStorage": "HIGH",
    "downloads": "HIGH",
    "tabs": "HIGH",
    "activeTab": "HIGH",
    "webNavigation": "HIGH",
    "webRequest": "HIGH",
    "management": "HIGH",
    "privacy": "HIGH",
    
    # MEDIUM - Moderate access
    "notifications": "MEDIUM",
    "contextMenus": "MEDIUM",
    "clipboardRead": "MEDIUM",
    "clipboardWrite": "MEDIUM",
    "geolocation": "MEDIUM",
    "identity": "MEDIUM",
    "identity.email": "MEDIUM",
    "desktopCapture": "MEDIUM",
    "pageCapture": "MEDIUM",
    "system.cpu": "MEDIUM",
    "system.memory": "MEDIUM",
    "system.storage": "MEDIUM",
    
    # LOW - Basic functionality
    "alarms": "LOW",
    "idle": "LOW",
    "power": "LOW",
    "printerProvider": "LOW",
    "printing": "LOW",
    "printingMetrics": "LOW",
    "scripting": "LOW",
    "sidePanel": "LOW",
    "storage.sync": "LOW",
    "topSites": "LOW",
    "tts": "LOW",
    "ttsEngine": "LOW",
    "nativeMessaging": "LOW",
}

# ============== OS DETECTION & PATH RESOLUTION ==============

def get_os_type() -> str:
    """Detect the operating system."""
    system = platform.system()
    if system == "Windows":
        return "windows"
    elif system == "Darwin":
        return "mac"
    elif system == "Linux":
        return "linux"
    return "unknown"

def get_chrome_extension_paths() -> List[Path]:
    """
    Get the default Chrome extension installation paths based on OS.
    Returns a list of possible paths (some may not exist).
    """
    os_type = get_os_type()
    home = Path.home()
    paths = []
    
    if os_type == "windows":
        # Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions
        local_app_data = os.environ.get("LOCALAPPDATA", home / "AppData" / "Local")
        paths.append(Path(local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Extensions")
        # Also check for Chrome Beta/Dev
        paths.append(Path(local_app_data) / "Google" / "Chrome Beta" / "User Data" / "Default" / "Extensions")
        paths.append(Path(local_app_data) / "Google" / "Chrome Dev" / "User Data" / "Default" / "Extensions")
        
    elif os_type == "mac":
        # macOS: ~/Library/Application Support/Google/Chrome/Default/Extensions
        paths.append(home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Extensions")
        paths.append(home / "Library" / "Application Support" / "Google" / "Chrome Beta" / "Default" / "Extensions")
        
    elif os_type == "linux":
        # Linux: ~/.config/google-chrome/Default/Extensions
        paths.append(home / ".config" / "google-chrome" / "Default" / "Extensions")
        paths.append(home / ".config" / "chromium" / "Default" / "Extensions")
        paths.append(home / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome" / "Default" / "Extensions")
    
    return paths

def find_valid_extension_path() -> Optional[Path]:
    """Find the first valid Chrome extension directory."""
    paths = get_chrome_extension_paths()
    for path in paths:
        if path.exists() and path.is_dir():
            return path
    return None

# ============== EXTENSION SCANNING ==============

def get_manifest_path(extension_id: str, base_path: Path) -> Optional[Path]:
    """
    Find the manifest.json path for a given extension ID.
    Chrome extensions are stored as: extension_id/version/manifest.json
    """
    ext_path = base_path / extension_id
    if not ext_path.exists():
        return None
    
    # Find version subdirectories
    version_dirs = [d for d in ext_path.iterdir() if d.is_dir()]
    
    if not version_dirs:
        return None
    
    # Sort by modification time to get the latest version
    version_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    for version_dir in version_dirs:
        manifest_path = version_dir / "manifest.json"
        if manifest_path.exists():
            return manifest_path
    
    return None

def parse_manifest(manifest_path: Path) -> Optional[Dict]:
    """Parse a manifest.json file and return its contents."""
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
        return None

def extract_extension_info(manifest: Dict, extension_id: str) -> Dict:
    """Extract relevant information from a manifest."""
    # Get extension name
    name = manifest.get("name", "Unknown Extension")
    
    # Handle localized names
    if name.startswith("__MSG_"):
        name = "Localized Extension"
    
    # Get version
    version = manifest.get("version", "Unknown")
    
    # Get description
    description = manifest.get("description", "No description available")
    if description.startswith("__MSG_"):
        description = "Localized description"
    
    # Get permissions
    permissions = manifest.get("permissions", [])
    
    # Also check host permissions
    host_permissions = manifest.get("host_permissions", [])
    
    # Check for content scripts permissions
    content_scripts = manifest.get("content_scripts", [])
    content_script_matches = []
    for script in content_scripts:
        matches = script.get("matches", [])
        content_script_matches.extend(matches)
    
    return {
        "id": extension_id,
        "name": name,
        "version": version,
        "description": description,
        "permissions": permissions,
        "host_permissions": host_permissions,
        "content_script_matches": content_script_matches,
        "manifest_version": manifest.get("manifest_version", 2)
    }

# ============== RISK SCORING ==============

def calculate_risk_score(extension_info: Dict) -> Tuple[int, List[Dict]]:
    """
    Calculate a privacy risk score (0-100) based on permissions.
    Returns the score and a list of risk details.
    """
    score = 0
    risk_details = []
    seen_permissions = set()
    
    all_permissions = extension_info.get("permissions", [])
    
    # Also factor in host permissions
    host_permissions = extension_info.get("host_permissions", [])
    if "<all_urls>" in host_permissions or "*://*/*" in host_permissions:
        if "all_urls" not in seen_permissions:
            all_permissions.append("all_urls")
    
    for permission in all_permissions:
        if permission in seen_permissions:
            continue
        seen_permissions.add(permission)
        
        risk_level = PERMISSION_RISKS.get(permission, "LOW")
        points = RISK_WEIGHTS[risk_level]
        
        # Add to score (cap at 100)
        score = min(100, score + points)
        
        risk_details.append({
            "permission": permission,
            "risk_level": risk_level,
            "points": points
        })
    
    # Sort by risk level (highest first)
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    risk_details.sort(key=lambda x: risk_order.get(x["risk_level"], 4))
    
    return score, risk_details

def get_risk_color(score: int) -> str:
    """Get a color based on risk score."""
    if score >= 70:
        return "#ff4444"  # Red - High Risk
    elif score >= 40:
        return "#ffaa00"  # Orange - Medium Risk
    elif score >= 20:
        return "#ffcc00"  # Yellow - Low-Medium Risk
    return "#44cc44"  # Green - Low Risk

def get_risk_label(score: int) -> str:
    """Get a risk label based on score."""
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    elif score >= 20:
        return "LOW-MEDIUM RISK"
    return "LOW RISK"

# ============== AI INTEGRATION (GROQ) ==============

def get_groq_client() -> Optional[OpenAI]:
    """Initialize Groq client with API key from session state."""
    api_key = st.session_state.get("groq_api_key", "")
    if not api_key:
        return None
    try:
        return OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1"
        )
    except Exception:
        return None

def analyze_with_ai(extension_info: Dict, risk_details: List[Dict]) -> str:
    """
    Use Groq AI to analyze permissions and explain risks in plain English.
    """
    client = get_groq_client()
    if not client:
        return "⚠️ Please enter your Groq API key in the sidebar to enable AI analysis."
    
    permissions = extension_info.get("permissions", [])
    host_permissions = extension_info.get("host_permissions", [])
    
    # Build the prompt
    prompt = f"""You are a cybersecurity expert explaining Chrome extension permissions to a beginner user.

Extension: {extension_info.get('name', 'Unknown')}
Description: {extension_info.get('description', 'No description')}

Permissions detected: {', '.join(permissions) if permissions else 'None'}
Host permissions: {', '.join(host_permissions) if host_permissions else 'None'}

Please provide a security analysis in the following format:

## 🔍 What This Extension Can Do
Explain in simple terms what access this extension has to the user's browser and data.

## ⚠️ Potential Privacy Risks
List specific risks based on the permissions. Use bullet points and explain each risk clearly.

## 🛡️ Real-World Attack Scenarios
Describe 2-3 realistic scenarios of how a malicious actor could abuse these permissions.

## ✅ Should You Be Concerned?
Give a balanced assessment - is this extension likely safe or should the user be cautious?

Keep your response concise, beginner-friendly, and actionable. Avoid overly technical jargon."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a helpful cybersecurity educator. Explain technical concepts in plain English."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ Error calling Groq API: {str(e)}\n\nPlease check your API key and try again."

# ============== STREAMLIT UI ==============

def init_session_state():
    """Initialize session state variables."""
    if "scanned_extensions" not in st.session_state:
        st.session_state.scanned_extensions = []
    if "selected_extension" not in st.session_state:
        st.session_state.selected_extension = None
    if "ai_analysis" not in st.session_state:
        st.session_state.ai_analysis = {}

def render_header():
    """Render the app header."""
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <h1 style="font-size: 3em; margin-bottom: 0;">🛡️ ManifestGuard</h1>
        <p style="font-size: 1.2em; color: #888;">AI-Powered Local Chrome Extension Auditor</p>
    </div>
    """, unsafe_allow_html=True)

def render_sidebar():
    """Render the sidebar with settings and info."""
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # API Key input
        api_key = st.text_input(
            "Groq API Key",
            type="password",
            value=st.session_state.get("groq_api_key", ""),
            help="Get your free API key at https://console.groq.com",
            key="groq_api_key_input"
        )
        st.session_state["groq_api_key"] = api_key
        
        st.divider()
        
        st.header("📊 Risk Score Guide")
        st.markdown("""
        | Score | Level | Color |
        |-------|-------|-------|
        | 70-100 | 🔴 HIGH | #ff4444 |
        | 40-69 | 🟠 MEDIUM | #ffaa00 |
        | 20-39 | 🟡 LOW-MED | #ffcc00 |
        | 0-19 | 🟢 LOW | #44cc44 |
        """)
        
        st.divider()
        
        st.header("🔐 Permission Weights")
        st.markdown(f"""
        - **CRITICAL**: {RISK_WEIGHTS['CRITICAL']} pts
        - **HIGH**: {RISK_WEIGHTS['HIGH']} pts
        - **MEDIUM**: {RISK_WEIGHTS['MEDIUM']} pts
        - **LOW**: {RISK_WEIGHTS['LOW']} pts
        """)
        
        st.divider()
        
        st.info("""
        **💡 Tip**: Most extensions need some permissions to function. 
        A high score doesn't mean an extension is malicious - 
        it just has powerful access to your browser.
        """)

def scan_extensions():
    """Scan for Chrome extensions and return the results."""
    base_path = find_valid_extension_path()
    
    if not base_path:
        return None, "Could not find Chrome extensions directory. Is Chrome installed?"
    
    extensions = []
    
    try:
        extension_ids = [d.name for d in base_path.iterdir() if d.is_dir()]
    except Exception as e:
        return None, f"Error reading extensions directory: {str(e)}"
    
    for ext_id in extension_ids:
        manifest_path = get_manifest_path(ext_id, base_path)
        if not manifest_path:
            continue
        
        manifest = parse_manifest(manifest_path)
        if not manifest:
            continue
        
        ext_info = extract_extension_info(manifest, ext_id)
        score, risk_details = calculate_risk_score(ext_info)
        
        extensions.append({
            "info": ext_info,
            "score": score,
            "risk_details": risk_details,
            "manifest_path": str(manifest_path)
        })
    
    # Sort by risk score (highest first)
    extensions.sort(key=lambda x: x["score"], reverse=True)
    
    return extensions, None

def render_extension_table(extensions: List[Dict]):
    """Render the extensions table."""
    st.subheader(f"📋 Found {len(extensions)} Extensions")
    
    # Create table data
    table_data = []
    for ext in extensions:
        info = ext["info"]
        score = ext["score"]
        color = get_risk_color(score)
        label = get_risk_label(score)
        
        table_data.append({
            "Name": info["name"],
            "Version": info["version"],
            "Risk Score": f"<span style='color: {color}; font-weight: bold;'>{score}/100</span>",
            "Risk Level": f"<span style='color: {color};'>{label}</span>",
            "Permissions": len(info["permissions"]),
            "Extension ID": info["id"][:20] + "..." if len(info["id"]) > 20 else info["id"]
        })
    
    # Display as dataframe
    import pandas as pd
    df = pd.DataFrame(table_data)
    
    # Use HTML for colored text
    st.markdown("""
    <style>
    .dataframe { font-size: 14px; }
    </style>
    """, unsafe_allow_html=True)
    
    # Display simple table without HTML first
    display_df = pd.DataFrame([
        {
            "Name": ext["info"]["name"],
            "Version": ext["info"]["version"],
            "Risk Score": f"{ext['score']}/100",
            "Risk Level": get_risk_label(ext["score"]),
            "Permissions": len(ext["info"]["permissions"]),
        }
        for ext in extensions
    ])
    
    st.dataframe(display_df, use_container_width=True, hide_index=True)

def render_extension_details(ext: Dict):
    """Render detailed view for a selected extension."""
    info = ext["info"]
    score = ext["score"]
    risk_details = ext["risk_details"]
    color = get_risk_color(score)
    label = get_risk_label(score)
    
    st.markdown(f"""
    <div style="background: linear-gradient(90deg, {color}22, transparent); 
                padding: 20px; border-radius: 10px; border-left: 5px solid {color};
                margin-bottom: 20px;">
        <h2 style="margin: 0;">{info['name']}</h2>
        <p style="margin: 5px 0; color: #888;">Version: {info['version']} | ID: {info['id']}</p>
        <div style="display: flex; align-items: center; gap: 15px; margin-top: 10px;">
            <span style="font-size: 2em; font-weight: bold; color: {color};">{score}/100</span>
            <span style="background: {color}; color: white; padding: 5px 15px; 
                        border-radius: 20px; font-weight: bold;">{label}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Description
    st.markdown("**📝 Description:**")
    st.info(info["description"] if info["description"] else "No description available")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("🔑 Permissions Breakdown")
        if risk_details:
            for detail in risk_details:
                risk_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[detail["risk_level"]]
                st.markdown(f"""
                <div style="padding: 8px; margin: 5px 0; 
                            background: {'#ff444422' if detail['risk_level'] == 'CRITICAL' else '#ffaa0022' if detail['risk_level'] == 'HIGH' else '#ffcc0022' if detail['risk_level'] == 'MEDIUM' else '#44cc4422'};
                            border-radius: 5px;">
                    <code>{detail['permission']}</code> 
                    <span style="float: right;">{risk_color} {detail['risk_level']} ({detail['points']} pts)</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("No special permissions requested")
    
    with col2:
        st.subheader("🌐 Host Permissions")
        host_perms = info.get("host_permissions", [])
        if host_perms:
            for perm in host_perms[:10]:  # Limit display
                st.code(perm, language=None)
            if len(host_perms) > 10:
                st.caption(f"... and {len(host_perms) - 10} more")
        else:
            st.info("No host permissions")
        
        # Content script matches
        matches = info.get("content_script_matches", [])
        if matches:
            st.subheader("📄 Content Script Matches")
            for match in matches[:5]:
                st.code(match, language=None)
    
    # AI Analysis
    st.divider()
    st.subheader("🤖 AI Security Analysis")
    
    ext_id = info["id"]
    
    # Check if we already have analysis cached
    if ext_id in st.session_state.ai_analysis:
        st.markdown(st.session_state.ai_analysis[ext_id])
    else:
        if st.button("🔍 Generate AI Analysis", key=f"analyze_{ext_id}"):
            with st.spinner("Analyzing with Groq AI..."):
                analysis = analyze_with_ai(info, risk_details)
                st.session_state.ai_analysis[ext_id] = analysis
                st.markdown(analysis)
        else:
            st.info("Click 'Generate AI Analysis' to get an AI-powered security breakdown of this extension.")

def main():
    """Main application entry point."""
    # Page config
    st.set_page_config(
        page_title="ManifestGuard - Chrome Extension Auditor",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    init_session_state()
    render_header()
    render_sidebar()
    
    # Main content
    st.markdown("""
    ### 🔍 Scan Your Chrome Extensions for Privacy Risks
    
    ManifestGuard automatically detects your locally installed Chrome extensions, 
    analyzes their permissions, and uses AI to explain potential privacy risks in plain English.
    """)
    
    # Scan button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        scan_button = st.button("🚀 Start Extension Scan", use_container_width=True, type="primary")
    
    if scan_button:
        with st.spinner("Scanning Chrome extensions..."):
            extensions, error = scan_extensions()
        
        if error:
            st.error(error)
            st.info(r"""
            **Troubleshooting:**
            - Make sure Chrome is installed on your system
            - On Windows: Check if Chrome is in `%LOCALAPPDATA%\Google\Chrome`
            - On Mac: Check `~/Library/Application Support/Google/Chrome`
            - On Linux: Check `~/.config/google-chrome`
            """)
        else:
            st.session_state.scanned_extensions = extensions
            st.success(f"✅ Found {len(extensions)} extensions!")
    
    # Display results if available
    if st.session_state.scanned_extensions:
        extensions = st.session_state.scanned_extensions
        
        # Summary metrics
        high_risk = sum(1 for e in extensions if e["score"] >= 70)
        medium_risk = sum(1 for e in extensions if 40 <= e["score"] < 70)
        low_risk = sum(1 for e in extensions if e["score"] < 40)
        
        st.divider()
        
        # Metrics row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Total Extensions", len(extensions))
        with m2:
            st.metric("🔴 High Risk", high_risk)
        with m3:
            st.metric("🟠 Medium Risk", medium_risk)
        with m4:
            st.metric("🟢 Low Risk", low_risk)
        
        st.divider()
        
        # Extension table
        render_extension_table(extensions)
        
        st.divider()
        
        # Extension selector for details
        st.subheader("🔎 View Extension Details")
        
        extension_options = [f"{e['info']['name']} (Score: {e['score']})" for e in extensions]
        selected = st.selectbox(
            "Select an extension to analyze:",
            options=range(len(extensions)),
            format_func=lambda i: extension_options[i]
        )
        
        if selected is not None:
            render_extension_details(extensions[selected])
    else:
        # Show info when no scan done yet
        st.info("👆 Click 'Start Extension Scan' above to begin auditing your Chrome extensions.")
        
        # Show sample of what will be detected
        with st.expander("📚 What permissions do we check?"):
            st.markdown("""
            ### Critical Permissions (40 points each)
            - `all_urls` / `<all_urls>` - Can read/modify ALL websites
            - `webRequestBlocking` - Can block/modify network requests
            - `debugger` - Can debug Chrome (very powerful)
            - `proxy` - Can control proxy settings
            
            ### High-Risk Permissions (20 points each)
            - `history` - Access to browsing history
            - `bookmarks` - Access to bookmarks
            - `cookies` - Access to all cookies
            - `tabs` - Can access all tabs
            - `storage` / `unlimitedStorage` - Can store unlimited data
            - `downloads` - Can download files
            
            ### Medium-Risk Permissions (10 points each)
            - `notifications` - Can show notifications
            - `clipboardRead/Write` - Can access clipboard
            - `geolocation` - Can access location
            - `identity` - Can access identity info
            
            ### Low-Risk Permissions (5 points each)
            - `alarms`, `idle`, `tts`, etc. - Basic functionality
            """)

if __name__ == "__main__":
    main()
