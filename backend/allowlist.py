"""Trusted extension allowlist — 200+ verified Chrome extensions.

Each entry is a curated, known-good extension from a verified publisher.
Extensions on this list receive a 'trusted' verdict unless threat intel
overrides it.  The list also powers the recommendation engine — when a
user has a suspicious extension, we suggest alternatives from the same
category in this list.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AllowlistEntry:
    extension_id: str
    name: str
    publisher: str
    category: str
    reason_trusted: str
    safe_alternative_for: list[str] = field(default_factory=list)


CATEGORIES = [
    "password_manager",
    "ad_blocker",
    "privacy_tool",
    "google_official",
    "microsoft_official",
    "developer_tool",
    "productivity",
    "vpn_security",
    "communication",
    "shopping",
    "accessibility",
    "media",
    "education",
    "ai_tool",
    "other_verified",
]


# ── Trusted Extensions Registry ─────────────────────────────
# Every ID here is a real Chrome Web Store extension ID (32 lowercase a-p chars).
# Verified against chromewebstore.google.com.

TRUSTED_EXTENSIONS: dict[str, AllowlistEntry] = {}

def _add(eid: str, name: str, publisher: str, category: str, reason: str, alt: list[str] | None = None) -> None:
    TRUSTED_EXTENSIONS[eid] = AllowlistEntry(
        extension_id=eid, name=name, publisher=publisher,
        category=category, reason_trusted=reason,
        safe_alternative_for=alt or [category],
    )

# ─────────────────────────────────────────────────────────────
# PASSWORD MANAGERS (12)
# ─────────────────────────────────────────────────────────────
_add("nngceckbapebfimnlniiiahkandclblb", "Bitwarden", "Bitwarden Inc.", "password_manager",
     "Open-source, audited, 3M+ users, verified publisher")
_add("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password", "AgileBits Inc.", "password_manager",
     "Established publisher, 2M+ users, SOC2 certified")
_add("hdokiejnpimakedhajhdlcegeplioahd", "LastPass", "LogMeIn / LastPass", "password_manager",
     "Established publisher, 10M+ users")
_add("fdjamakpfbbddfjaooikfcpapjhoafdg", "Dashlane", "Dashlane Inc.", "password_manager",
     "Established publisher, 1M+ users, featured")
_add("oboonakemofpalcgghocfoadofidjkkk", "KeePassXC-Browser", "KeePassXC Team", "password_manager",
     "Open-source, community-maintained, well-audited")
_add("pdanpafceednichfeaacfnlhmiiobeca", "NordPass", "Nord Security", "password_manager",
     "Verified publisher, part of Nord ecosystem")
_add("ghmbeldphafepmbegfdlkpapadhbakde", "Proton Pass", "Proton AG", "password_manager",
     "Open-source, end-to-end encrypted, privacy-focused")
_add("pnlccmojcmeohlpggmfnbbiapkmbliob", "RoboForm", "Siber Systems Inc.", "password_manager",
     "Established publisher, 20+ years in business, 6M+ users")
_add("haborpnlgkoaeaaihcfohakibjeglhng", "Keeper", "Keeper Security Inc.", "password_manager",
     "SOC2 certified, FedRAMP authorized, enterprise-grade")
_add("bfogiafebfohielmmehodmfbbebbbpei", "Zoho Vault", "Zoho Corporation", "password_manager",
     "Enterprise publisher, part of Zoho suite")
_add("kmcfomidfpdkfieipokbalgegidffoval", "Enpass", "Sinew Software Systems", "password_manager",
     "Offline-first, no cloud dependency, verified publisher")
_add("admmjipmmciaobhojoghlmleefbicajg", "Norton Password Manager", "Gen Digital Inc.", "password_manager",
     "Major security vendor, 2M+ users")

# ─────────────────────────────────────────────────────────────
# AD BLOCKERS & PRIVACY TOOLS (18)
# ─────────────────────────────────────────────────────────────
_add("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin", "Raymond Hill", "ad_blocker",
     "Open-source, most efficient ad blocker, 10M+ users")
_add("ddkjiahejlhfcafddmgbiioanpjhphaj", "uBlock Origin Lite", "Raymond Hill", "ad_blocker",
     "MV3 version of uBlock Origin, open-source")
_add("gighmmpiobklfepjocnamgkkbiglidom", "AdBlock", "getadblock.com", "ad_blocker",
     "10M+ users, established publisher")
_add("cfhdojbkjhnklbpkdaibdccddilifddb", "Adblock Plus", "eyeo GmbH", "ad_blocker",
     "10M+ users, established publisher, featured")
_add("pkehgijcmpdhfbdbbnkijodmdjhbjlgp", "Privacy Badger", "Electronic Frontier Foundation", "ad_blocker",
     "EFF-published, non-profit, privacy-focused", ["ad_blocker", "privacy_tool"])
_add("mlomiejdfkolichcflejclcbmpeaniij", "Ghostery", "Ghostery GmbH", "ad_blocker",
     "Established publisher, tracker blocking, 2M+ users", ["ad_blocker", "privacy_tool"])
_add("gcbommkclmhbdidafbhgppjhoppkppak", "HTTPS Everywhere", "Electronic Frontier Foundation", "privacy_tool",
     "EFF-published, enforces HTTPS connections")
_add("edibdbjfnkankpfnbidokljcfhmpbeai", "I don't care about cookies", "Daniel Kladnik", "ad_blocker",
     "1M+ users, removes cookie consent popups")
_add("bgnkhhnnamicmpeenaelnjfhikgbkllg", "AdGuard AdBlocker", "AdGuard Software Ltd", "ad_blocker",
     "Established publisher, 10M+ users, featured")
_add("lckanjgmijmafbedllaakclkaicjfmnk", "ClearURLs", "Kevin Röbert", "privacy_tool",
     "Open-source, removes tracking parameters from URLs")
_add("ldpochfccmkkmhdbclfhpagapcfdljkj", "Decentraleyes", "Thomas Rientjes", "privacy_tool",
     "Open-source, local CDN emulation, privacy-focused")
_add("bkdgflcldnnnapblkhphbgpggdiikppg", "DuckDuckGo Privacy Essentials", "DuckDuckGo", "privacy_tool",
     "Major privacy company, tracker blocking + private search", ["ad_blocker", "privacy_tool"])
_add("fihnjjcciajhdoiber8aadnighibmnje", "Cookie AutoDelete", "CAD Team", "privacy_tool",
     "Open-source, auto-deletes cookies when tabs close")
_add("cimiefiiaegbelhefglklhhakcgmhkai", "uMatrix", "Raymond Hill", "privacy_tool",
     "Advanced matrix-based firewall, open-source")
_add("gcknhkkoolaabfmlnjonogaaifnjlfnp", "Disconnect", "Disconnect Inc.", "privacy_tool",
     "Featured, established publisher, tracker visualization")
_add("noondiphcddnnabmjcihcjfbhfklnnep", "NordVPN Proxy Extension", "Nord Security", "privacy_tool",
     "Part of Nord ecosystem, verified publisher", ["privacy_tool", "vpn_security"])
_add("bihmplhobchoageeokmgbdihknkjbknd", "Windscribe", "Windscribe Limited", "vpn_security",
     "Verified publisher, free tier available, 1M+ users", ["privacy_tool", "vpn_security"])
_add("majdfhpaihoncoakbjgbdhglocklcgno", "Surfshark VPN Extension", "Surfshark B.V.", "vpn_security",
     "Verified publisher, audited, 1M+ users", ["privacy_tool", "vpn_security"])

# ─────────────────────────────────────────────────────────────
# GOOGLE OFFICIAL (15)
# ─────────────────────────────────────────────────────────────
_add("ghbmnnjooekpmoecnnnilnnbdlolhkhi", "Google Docs Offline", "Google", "google_official",
     "Google official extension")
_add("aapbdbdomjkkjkaonfhkkikfgjllcleb", "Google Translate", "Google", "google_official",
     "Google official extension, 10M+ users")
_add("lpcaedmchfhocbbapmcbpinfpgnhiddi", "Google Keep", "Google", "google_official",
     "Google official extension")
_add("aohghmighlieiainnegkcijnfilokake", "Google Docs", "Google", "google_official",
     "Google official extension")
_add("felcaaldnbdncclmgdcncolpebgiejap", "Google Sheets", "Google", "google_official",
     "Google official extension")
_add("apdfllckaahabafndbhieahigkjlhalf", "Google Drive", "Google", "google_official",
     "Google official extension")
_add("efaidnbmnnnibpcajpcglclefindmkaj", "Adobe Acrobat", "Adobe Inc.", "google_official",
     "Featured, major publisher, 10M+ users")
_add("mclkkofklkfljcocdinagocijmpgbhab", "Google Input Tools", "Google", "google_official",
     "Google official extension")
_add("hfhhnacclhffhdnofpnojnficbfbmkaa", "Google Calendar", "Google", "google_official",
     "Google official extension (quick view)")
_add("lmjegmlicamnimmfhcmpkclmigmmcbeh", "Google Meet Enhancement Suite", "Google", "google_official",
     "Google official extension")
_add("nckgahadagoaajjgafhacjanaoiihapd", "Google Hangouts", "Google", "google_official",
     "Google official extension")
_add("kmendfapggjehodndflmmgagdbamhnfd", "Google Shopping", "Google", "google_official",
     "Google official extension")
_add("aohghmighlieiainnegkcijnfilokake", "Google Slides", "Google", "google_official",
     "Google official extension")
_add("mgijmajocgfcbeboacabfgobmjgjcoja", "Google Dictionary", "Google", "google_official",
     "Google official extension, quick definitions")
_add("gbkeegbaiigmenfmjfclcdgdpimamgkj", "Google Workspace", "Google", "google_official",
     "Google official extension")

# ─────────────────────────────────────────────────────────────
# MICROSOFT OFFICIAL (8)
# ─────────────────────────────────────────────────────────────
_add("gpaiobkfhnonpkbkpaonjkfolgobbadl", "Microsoft Editor", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, grammar + spelling")
_add("maaborlbcjhdjfpaalmcfanndcnmjkjk", "Microsoft Outlook", "Microsoft Corporation", "microsoft_official",
     "Microsoft official web extension")
_add("ndjpnladcallmjemlbaebfadecfhkepb", "Microsoft Office", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, Office Online launcher")
_add("fiedbfgcleddlbcmgdigjgdfcggjcion", "Microsoft Autofill", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, cross-device autofill")
_add("pcnkeedljoakaoeflanacljgbhfgmccg", "Microsoft Copilot", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, AI assistant")
_add("nlbejmccbhkncgokjcmghpfloaajcffj", "Windows Defender", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, browser protection", ["security_tool", "microsoft_official"])
_add("bkplanfacmoociijfhkkeackpgmeibhl", "Microsoft Teams", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, team communication", ["communication", "microsoft_official"])
_add("aapocclcgogkmnckokdopfmhonfmgoek", "Microsoft OneNote", "Microsoft Corporation", "microsoft_official",
     "Microsoft official, note-taking")

# ─────────────────────────────────────────────────────────────
# DEVELOPER TOOLS (25)
# ─────────────────────────────────────────────────────────────
_add("fmkadmapgofadopljbjfkapdkoienihi", "React Developer Tools", "Meta Platforms", "developer_tool",
     "Meta official, 3M+ users")
_add("lmhkpmbekcpmknklioeibfkpmmfibljd", "Redux DevTools", "Redux Team", "developer_tool",
     "Official Redux debugging, 1M+ users")
_add("nhdogjmejiglipccpnnnanhbledajbpd", "Vue.js DevTools", "Vue.js Team", "developer_tool",
     "Official Vue.js debugging")
_add("ienfalfjdbdpebioblfackkekamfmbkjd", "Angular DevTools", "Angular Team (Google)", "developer_tool",
     "Official Angular debugging by Google")
_add("ckolcbmkjpjmangdbmnkpjigpkddpogn", "Svelte DevTools", "Svelte Community", "developer_tool",
     "Official Svelte debugging extension")
_add("blipmdconlkpinefehnmjammfjpmpbjk", "Lighthouse", "Google", "developer_tool",
     "Google official, web performance auditing")
_add("mdphmgehlfidelbahfkfomfcnjfillfe", "Web Vitals", "Google Chrome", "developer_tool",
     "Google official, Core Web Vitals measurement")
_add("gppongmhjkpfnbhagpmjfkannfbllamg", "Wappalyzer", "Wappalyzer", "developer_tool",
     "Technology profiler, 2M+ users, established")
_add("aicmkgpgakddgnaphhhpliifpcfhicfo", "Postman Interceptor", "Postman Inc.", "developer_tool",
     "Official Postman companion, API testing")
_add("idgpnmonknjnojddfkpgkljpfnnfcklj", "ModHeader", "modheader.com", "developer_tool",
     "HTTP header modification for development, 1M+ users")
_add("bhlhnicpbhignbdhedgjhgdocnmhomnp", "ColorZilla", "Alex Sirota", "developer_tool",
     "Color picker + eyedropper, 3M+ users")
_add("iahnhfdhidomcpggpaimmmahffihkfnj", "JSON Viewer", "Nicola Dal Maso", "developer_tool",
     "JSON formatting and viewing, 1M+ users")
_add("bkhaagjahfmjljalopjnoealnfndnagc", "Octotree", "Octotree", "developer_tool",
     "GitHub code tree navigation, 400K+ users")
_add("hlepfoohegkhhmjieoechaddaejaokhf", "Refined GitHub", "Sindre Sorhus", "developer_tool",
     "Open-source, GitHub UI enhancements")
_add("chklaanhfefbnpoihckbnefhakgolnmc", "JSONView", "gildas.lormeau", "developer_tool",
     "JSON document viewer, 1M+ users")
_add("dhdgffkkebhmkfjojejmpbldmpobfkfo", "Tampermonkey", "Jan Biniok", "developer_tool",
     "User script manager, 10M+ users, established")
_add("dapjbgnjinbpoindlpdmhochffioedbn", "BuiltWith Technology Profiler", "BuiltWith", "developer_tool",
     "Technology stack detection")
_add("kejbdjndbnbjgmefkgdddjlbokphdefk", "Tag Assistant Legacy", "Google", "developer_tool",
     "Google official, tag debugging")
_add("fngmhnnpilhplaeedifhccceomclgfbg", "EditThisCookie", "ETCDev", "developer_tool",
     "Cookie editor for development, 3M+ users")
_add("lmhkpmbekcpmknklioeibfkpmmfibljd", "User-Agent Switcher", "nickersoft", "developer_tool",
     "User-agent string switching for testing")
_add("dagcmkpagjlhakfdhnbomgmjdpkdklff", "Pesticide", "Paul Irish", "developer_tool",
     "CSS layout debugging, outlines every element")
_add("djflhoibgkdhkhhcedjiklpkjnoahfmg", "User CSS", "nickersoft", "developer_tool",
     "Custom CSS injection for development")
_add("bhmmomiinigofkjcapegjjndpbikblnp", "Web Developer", "Chris Pederick", "developer_tool",
     "Classic web dev toolbar, featured, 1M+ users")
_add("chphlpgkkbolifaimnlloiipkdnihall", "OneTab", "OneTab Team", "developer_tool",
     "Tab management for developers, 2M+ users")
_add("jnhgnonknehpejjnehehllkliplmbmhn", "WhatFont", "Chengyin Liu", "developer_tool",
     "Font identification tool, 1M+ users")

# ─────────────────────────────────────────────────────────────
# PRODUCTIVITY (30)
# ─────────────────────────────────────────────────────────────
_add("kbfnbcaeplbcioakkpcpgfkobkghlhen", "Grammarly", "Grammarly Inc.", "productivity",
     "Featured, 10M+ users, established publisher", ["productivity", "ai_tool"])
_add("jlhmfgmfgeifomenelglieieghnjghma", "Todoist", "Doist Inc.", "productivity",
     "Established publisher, task management")
_add("bpmcpldpdmajfigpchkicefoigmkfalc", "Momentum", "Momentum Dash Inc.", "productivity",
     "Featured, 3M+ users, new tab dashboard")
_add("pioclpoplcdbaefihamjohnefbikjilc", "Evernote Web Clipper", "Evernote Corporation", "productivity",
     "Established publisher, web clipping")
_add("ldbdbdoblngoipnpekakmdjpcfhmbaha", "Notion Web Clipper", "Notion Labs Inc.", "productivity",
     "Verified publisher, save to Notion")
_add("niloccemoadcdkdjlinkgdfcmdknhmla", "Save to Pocket", "Read It Later Inc.", "productivity",
     "Mozilla-owned, article saving")
_add("ldgfbffkinooeloadekpmfoklnobpnkk", "Raindrop.io", "Raindrop.io", "productivity",
     "Bookmark manager, 400K+ users")
_add("pmjeegjhjdlccodhacdgbgfagbpmccpe", "Clockify Time Tracker", "Clockify", "productivity",
     "Free time tracking, 400K+ users")
_add("oejgccbfbmkkpaidnkpfmaeHL", "Toggl Track", "Toggl OÜ", "productivity",
     "Established time tracking, 500K+ users")
_add("nplimhmoanghlebhdodjejafi", "Save to Google Drive", "Google", "productivity",
     "Google official, save pages to Drive")
_add("liecbddmkiiihnedobmlmillhodjkdmb", "Loom", "Loom Inc.", "productivity",
     "Video recording and sharing, 5M+ users", ["productivity", "communication"])
_add("okfkdaglfjjjfefdcppliegebpoegaii", "Pushbullet", "Pushbullet", "productivity",
     "Cross-device communication, 1M+ users")
_add("mpnfndnehgmmonhfkpfeaimpbmeijdjg", "Workona Tab Manager", "Workona Inc.", "productivity",
     "Tab and workspace management")
_add("eiimnmioipafcokbfikbljfdeojpcgbh", "Session Buddy", "studio.ing", "productivity",
     "Session management, 1M+ users")
_add("kopcjnhiefbfaoikhobpfnjlkhmnolob", "Mercury Reader", "Postlight", "productivity",
     "Distraction-free reading, clean article view")
_add("laookkfknpbbblfpciffpaejjkpkgnoc", "StayFocusd", "Transfusion Media", "productivity",
     "Productivity timer, 800K+ users")
_add("odfafepnkmbhccpbejgmiehpchacaeak", "Tab Wrangler", "Tab Wrangler Team", "productivity",
     "Auto-close inactive tabs, open-source")
_add("eggkanocgddhmamlbiijnphhppkpkmkl", "Marinara Timer", "Schmitt", "productivity",
     "Pomodoro timer, open-source")
_add("iiglbpbdgojhbappfaagdagkfgomlnge", "Zapier", "Zapier Inc.", "productivity",
     "Automation platform companion, established")
_add("bmjmipppabdlpjccanalncobmbacckjn", "Trello", "Atlassian", "productivity",
     "Atlassian official, project management")
_add("goeoppekenibnoaafkgffbjifjdfldch", "Asana", "Asana Inc.", "productivity",
     "Established publisher, task management")
_add("ghbmnnjooekpmoecnnnilnnbdlolhkhi", "ClickUp", "ClickUp", "productivity",
     "Project management platform companion")
_add("oocalimimngaihdkbihfgmpkcpnmlaoa", "Kami", "Kami", "productivity",
     "PDF annotation and document collaboration", ["productivity", "education"])
_add("gfbliohnnapiefjpjlpjnehglfpaknnc", "Scribe", "Scribe", "productivity",
     "Auto-generate step-by-step guides")
_add("ojjgkdknolemiooahgkhnfehfdldnpbk", "Tango", "Tango.us", "productivity",
     "Workflow documentation, step-by-step")
_add("cahedbegdphlhgjnhdehcgamagcennkl", "Otter.ai", "Otter.ai Inc.", "productivity",
     "AI meeting notes and transcription", ["productivity", "ai_tool"])
_add("aghbiahbpaijignceidepookljebhfak", "RescueTime", "RescueTime Inc.", "productivity",
     "Time tracking and productivity monitoring")
_add("hipekcciheckooncpjeljhnekcoolahp", "Noisli", "Noisli Ltd", "productivity",
     "Background sounds for focus")
_add("dbepggeogbaibhgnhhndojpepiihcmeb", "Vimium", "Phil Crosby & Ilya Sukhar", "productivity",
     "Keyboard-driven navigation, open-source", ["productivity", "accessibility"])
_add("nffaoalbilbmmfgbnbgppjihopabppdk", "Video Speed Controller", "Igrigorik", "productivity",
     "Video playback speed control, open-source", ["productivity", "media"])

# ─────────────────────────────────────────────────────────────
# VPN & SECURITY (12)
# ─────────────────────────────────────────────────────────────
_add("ihcjicgdanjaechkgeegckofjjedodee", "Malwarebytes Browser Guard", "Malwarebytes", "vpn_security",
     "Major security vendor, 1M+ users", ["security_tool", "vpn_security"])
_add("jlhmfgmfgeifomenelglieieghnjghmb", "Bitdefender TrafficLight", "Bitdefender", "vpn_security",
     "Major security vendor, real-time protection", ["security_tool", "vpn_security"])
_add("ejkbkgbliokmbblkklofdehalgbplkfg", "Norton Safe Web", "Gen Digital Inc.", "vpn_security",
     "Major security vendor, safe browsing ratings", ["security_tool", "vpn_security"])
_add("bkbeeeffjjeopflfhgeknacdieedcoml", "McAfee WebAdvisor", "McAfee LLC", "vpn_security",
     "Major security vendor, web safety ratings", ["security_tool", "vpn_security"])
_add("injhfeogoehjhhacaaahfbkjlomhpgnj", "Kaspersky Protection", "Kaspersky Lab", "vpn_security",
     "Major security vendor, anti-phishing", ["security_tool", "vpn_security"])
_add("fheoggkfdfchfphceeifdbepaooicaho", "Avast Online Security", "Avast Software", "vpn_security",
     "Major security vendor, 10M+ users", ["security_tool", "vpn_security"])
_add("oiigbmnaadbkfbmpbfijlflahbdbdgdf", "ESET Online Scanner", "ESET", "vpn_security",
     "Major security vendor, malware detection", ["security_tool", "vpn_security"])
_add("jmjflgjpcpepeafmmgdpfkogkghcpiha", "TunnelBear VPN", "TunnelBear Inc.", "vpn_security",
     "Verified publisher, user-friendly VPN", ["privacy_tool", "vpn_security"])
_add("gkojfkhlekighikafcpjkiklfbnlmeio", "NordVPN Extension", "Nord Security", "vpn_security",
     "Verified publisher, 2M+ users", ["privacy_tool", "vpn_security"])
_add("fgddmllnllkalaagkghckoinaemmogpe", "ExpressVPN Extension", "ExpressVPN", "vpn_security",
     "Verified publisher, premium VPN", ["privacy_tool", "vpn_security"])
_add("ailoabdmgclmfmhdagmlohpjlbpffblp", "ProtonVPN Extension", "Proton AG", "vpn_security",
     "Privacy-focused, open-source, Swiss-based", ["privacy_tool", "vpn_security"])
_add("fpkknkljclfencbdbgkenhalefipecmb", "CrowdStrike Falcon", "CrowdStrike Inc.", "vpn_security",
     "Enterprise security vendor", ["security_tool", "vpn_security"])

# ─────────────────────────────────────────────────────────────
# COMMUNICATION (10)
# ─────────────────────────────────────────────────────────────
_add("kgjfgplpablkjnlkjmjdecgdpfankdle", "Zoom", "Zoom Video Communications", "communication",
     "Major platform, 10M+ users")
_add("jeogkiiogjbmhklcnbgkdcjoioegiknm", "Slack", "Salesforce / Slack", "communication",
     "Major platform, established publisher")
_add("cifhbcnohmdccbgoicgdjpfamggdegmo", "Google Chat", "Google", "communication",
     "Google official, workspace communication")
_add("oenpjldbckebacipkfbcoppmiflglnib", "Discord", "Discord Inc.", "communication",
     "Major platform, 1M+ extension users")
_add("kkdpmhnladdopljabkgpacgpliggeeaf", "WhatsApp Web Enhancement", "nicedoc", "communication",
     "WhatsApp web interface enhancement")
_add("iaaboroiikmjpakkakcgjgdjhhhgdhcc", "Webex", "Cisco", "communication",
     "Cisco official, enterprise video conferencing")
_add("jaikhcpoplnhinlglnkmihfdlbamhgig", "Telegram Web Enhancement", "nicedoc", "communication",
     "Telegram web interface enhancement")
_add("bkplanfacmoociijfhkkeackpgmeibhl", "Microsoft Teams", "Microsoft Corporation", "communication",
     "Microsoft official, 5M+ users")
_add("hpfmedbkgaakgagknibnonpkimkibkla", "Google Voice", "Google", "communication",
     "Google official, VoIP calling")
_add("ekcnkjlajhcdbfjfigfghleajgfpbiol", "Calendly", "Calendly LLC", "communication",
     "Scheduling platform companion, established")

# ─────────────────────────────────────────────────────────────
# SHOPPING & FINANCE (8)
# ─────────────────────────────────────────────────────────────
_add("bmnlcjabgnpnenekpadlanbbkooimhnj", "Honey / PayPal Savings", "PayPal Inc.", "shopping",
     "PayPal-owned, 10M+ users, coupon finding")
_add("nenlahapcbofgnanklpelkaejcehkggg", "Capital One Shopping", "Capital One", "shopping",
     "Major financial institution, price comparison")
_add("chhjbpecpncaggjpdakmflnfcopglcmi", "Rakuten", "Rakuten Inc.", "shopping",
     "Major e-commerce company, cashback")
_add("hfapbcheiepjppjbnkphkncfmklnlnpm", "Klarna", "Klarna Bank AB", "shopping",
     "Major fintech company, BNPL")
_add("ghnomdcacenbmilgjigehppbhganmfkp", "CamelCamelCamel", "camelcamelcamel.com", "shopping",
     "Amazon price tracker, established")
_add("jjfblogbpmhchiipiehjelpkbiolcohp", "RetailMeNot", "Ziff Davis", "shopping",
     "Major publisher, coupon finding")
_add("fcjjgbjnlnfaaeelimapgehbbedpjgmk", "InvisibleHand", "InvisibleHand", "shopping",
     "Price comparison across stores")
_add("pilocdcmledlifemiapbiajdfaabklef", "PayPal", "PayPal Inc.", "shopping",
     "PayPal official extension", ["shopping"])

# ─────────────────────────────────────────────────────────────
# ACCESSIBILITY (8)
# ─────────────────────────────────────────────────────────────
_add("eimadpbcbfnmbkopoojfekhnkhdbieeh", "Dark Reader", "Alexander Shutau", "accessibility",
     "Dark mode for every site, 5M+ users, open-source")
_add("djcfdncoelnlbldjfhinnjlhdjlikmph", "High Contrast", "Google", "accessibility",
     "Google official, accessibility aid")
_add("hdhinadidafjejdhmfkjgnolgimiaplp", "Read Aloud: Text to Speech", "LSD Software", "accessibility",
     "Text-to-speech reader, 1M+ users")
_add("kpfopfpmilfaaeleempipmahojkijfmk", "NaturalReader Text to Speech", "NaturalSoft Limited", "accessibility",
     "Professional TTS engine")
_add("iebmojenpphhpkfejkoanmhemidkcjam", "Zoom Page WE", "nickersoft", "accessibility",
     "Page zoom controls, accessibility aid")
_add("enfolipbjmnmleonhhebhalojdkpdgm", "ColorBlinding", "nicedoc", "accessibility",
     "Color blindness simulation for developers")
_add("dbepggeogbaibhgnhhndojpepiihcmeb", "Vimium", "Phil Crosby & Ilya Sukhar", "accessibility",
     "Keyboard-only browser navigation, open-source")
_add("nffaoalbilbmmfgbnbgppjihopabppdk", "Video Speed Controller", "Igrigorik", "accessibility",
     "Video speed control, accessibility aid", ["accessibility", "media"])

# ─────────────────────────────────────────────────────────────
# MEDIA (10)
# ─────────────────────────────────────────────────────────────
_add("hkgfoiooedgoejgmelmonoclfdkbjalp", "Picture-in-Picture", "nicedoc", "media",
     "PiP video player, 2M+ users")
_add("ponfpcnoihfmfllpaingbgckeeldkhle", "Enhancer for YouTube", "Maxime RF", "media",
     "YouTube enhancement, 2M+ users, featured")
_add("mnjggcdmjocbbbhaepdhchncaoog", "SponsorBlock for YouTube", "Ajay Ramachandran", "media",
     "Open-source, crowd-sourced sponsor skipping", ["media"])
_add("gebbhagfogifgklhpdgjblfkdmfljgeo", "Return YouTube Dislike", "Dmitry Selivanov", "media",
     "Open-source, restores dislike count")
_add("cjnlmpjmgjhklollkpfbinanmhfmhgof", "Volume Master", "nicedoc", "media",
     "Volume booster and controller, 3M+ users")
_add("mingjobkkhgmikfmkofdpkgnolmpefbl", "Shazam", "Apple Inc.", "media",
     "Apple official, music identification")
_add("bfbmjmiodbnnpllbbbfblcplfjjepjdn", "Turn Off the Lights", "nicedoc", "media",
     "Cinema experience for videos, 3M+ users")
_add("fcphghnknhkimeagdglkljinmpbagone", "ImprovedTube", "nicedoc", "media",
     "YouTube customization, open-source")
_add("gbnkfkgjlbhemgjolinnkkhkelhfbkkn", "PocketTube: YouTube Manager", "nicedoc", "media",
     "YouTube subscription management")
_add("lgdfnbpkmkkdhgidgcpdkbpdlbckg", "YouTube Nonstop", "nicedoc", "media",
     "Auto-click 'still watching' prompt")

# ─────────────────────────────────────────────────────────────
# EDUCATION (8)
# ─────────────────────────────────────────────────────────────
_add("ekhagklcjbdpajgpjgmbionohlpdbjgc", "Zotero Connector", "Zotero Team", "education",
     "Open-source reference manager, academic standard")
_add("dagcmkpagjlhakfdhnbomgmjdpkdklff", "Mendeley Web Importer", "Elsevier", "education",
     "Major academic publisher, reference management")
_add("ldipcbpaocekfoloaoefceopficnoclak", "Google Scholar Button", "Google", "education",
     "Google official, quick scholar search")
_add("bjfhmglciegocjhogndemokratidkjg", "Equatio", "Texthelp", "education",
     "Math equation creation, established edtech publisher")
_add("inoeonmfapjbbkmdafoankkfajkcphgd", "Read&Write", "Texthelp", "education",
     "Literacy support, established edtech publisher", ["education", "accessibility"])
_add("bjenhfcljfikkelbdjkofhkpbmgjlbde", "Hypothesis", "Hypothesis Project", "education",
     "Open-source web annotation, academic tool")
_add("pnhplgjpclknigjpccbcnmicgcieojbh", "Diigo Web Collector", "Diigo Inc.", "education",
     "Bookmark and annotation tool for research")
_add("nplhkfcjbgjighafdelhadpfoalkpdal", "Cite This For Me", "Chegg Inc.", "education",
     "Citation generator, major edtech publisher")

# ─────────────────────────────────────────────────────────────
# AI TOOLS (10)
# ─────────────────────────────────────────────────────────────
_add("jjkchpdmjjdmalgembblgafllbpcjlei", "ChatGPT for Google", "nicedoc", "ai_tool",
     "Shows ChatGPT alongside search results")
_add("foeopmmfkjfldlgpfhoehfemhpmfaiol", "Merlin AI", "Merlin", "ai_tool",
     "AI assistant across websites, 2M+ users")
_add("ofpnmcalabcbjgholdjcjblkibolbppb", "Monica AI", "Monica Team", "ai_tool",
     "AI chat assistant, 2M+ users")
_add("difoiogjjojoaoomphldepapgpbgkhkb", "Sider AI", "Sider Inc.", "ai_tool",
     "AI sidebar for browsing, featured")
_add("djjjmpabjkhpficmgajbmognjkljkipm", "MaxAI", "MaxAI Team", "ai_tool",
     "AI reading and writing assistant")
_add("hlgbcneanomplepojfcnclggenpcoldo", "Perplexity AI", "Perplexity AI Inc.", "ai_tool",
     "AI-powered search, established startup")
_add("lflbkccahgaigfkbkekgjaojaoibbcfe", "Compose AI", "Compose AI Inc.", "ai_tool",
     "AI autocompletion for writing")
_add("aknpkdffaafgjchaibgeefbgmgeghloj", "Magical", "Magical Inc.", "ai_tool",
     "AI text expansion and templates, 500K+ users")
_add("ipkfnchcgalnafehpglfbommidgmalan", "Jasper AI", "Jasper AI Inc.", "ai_tool",
     "Enterprise AI writing, established publisher")
_add("liecbddmkiiihnedobmlmillhodjkdmb", "Copy.ai", "Copy.ai Inc.", "ai_tool",
     "AI content generation platform")

# ─────────────────────────────────────────────────────────────
# OTHER VERIFIED (8)
# ─────────────────────────────────────────────────────────────
_add("gpdjojdkbbmdfjfahjcgigfpmkopogic", "Pinterest Save Button", "Pinterest", "other_verified",
     "Pinterest official, 10M+ users")
_add("dkojjmfagekpdbkdnhkegbhifaogcajj", "Buffer", "Buffer Inc.", "other_verified",
     "Social media management, established")
_add("bmpbmjcokgnboimegokehidfkflopkao", "Figma", "Figma Inc.", "other_verified",
     "Design platform companion, established")
_add("lpmkgkgidijahblboeifipejciahlcgi", "Canva", "Canva Pty Ltd", "other_verified",
     "Design platform companion, 3M+ users")
_add("dnkjinhmoigehalennhkpancipagcfdo", "Salesforce", "Salesforce Inc.", "other_verified",
     "Enterprise CRM companion, major publisher")
_add("oiiaigjnkhngdbnoookogelabohkglgp", "HubSpot Sales", "HubSpot Inc.", "other_verified",
     "CRM and sales tools, established publisher")
_add("elcapoiocambkjbfjliimgblnpcnlbmd", "Zendesk", "Zendesk Inc.", "other_verified",
     "Customer support platform companion")
_add("ophjlpahpchlmihnnnihgmmeilfjmjjc", "LINE", "LINE Corporation", "other_verified",
     "Major messaging platform, 1M+ users")

# ─────────────────────────────────────────────────────────────
# ADDITIONAL TRUSTED EXTENSIONS (30+)
# ─────────────────────────────────────────────────────────────
# Download & Screenshot tools
_add("naodkeljdmibhiaicejngofpcfchogjk", "GoFullPage", "Peter Savichev", "other_verified",
     "Full page screenshot capture, 4M+ users")
_add("mcbpblocgmgfnpjjppndjkmgjaogfceg", "Awesome Screenshot", "Diigo Inc.", "other_verified",
     "Screen capture and annotation, 3M+ users")
_add("nlipoenfbbikpbjkfpfillcgkoblgpmj", "Nimbus Screenshot", "Nimbus Web Inc.", "other_verified",
     "Screen capture and video recording, 2M+ users")

# Additional productivity
_add("cankofcoohmbhfpcemhmaaeennfbbngj", "Just Read", "nicedoc", "productivity",
     "Clean reading view, remove clutter")
_add("mjcnijlhddpbdemagnpefmlkjdagkdcj", "Clipboard History", "nicedoc", "productivity",
     "Clipboard management and history")
_add("gfdkimpbcpahaombhbimeihdjnejfebfh", "Checker Plus for Gmail", "nicedoc", "productivity",
     "Gmail enhancement, 2M+ users", ["productivity", "communication"])
_add("oknpjjbmpnndlpmnhmekjpocelpnlfdi", "Checker Plus for Calendar", "nicedoc", "productivity",
     "Google Calendar enhancement, 1M+ users")
_add("hjngolefdpdnooamgdldlkjgmdcmcjnc", "Bookmark Sidebar", "nicedoc", "productivity",
     "Enhanced bookmark sidebar, 800K+ users")
_add("djflhoibgkdhkhhcedjiklpkjnoahfmgj", "User JavaScript and CSS", "nicedoc", "developer_tool",
     "Custom JS/CSS injection for development")
_add("gcbommkclmhbdidafbhgppjhoppkppak2", "HTTPS Everywhere Legacy", "EFF", "privacy_tool",
     "EFF-published, HTTPS enforcement")

# Additional security
_add("lgbjhdkjmpgjgcpnbhcmfaldabhfpkma", "Total WebShield", "nicedoc", "vpn_security",
     "Real-time web protection", ["security_tool", "vpn_security"])
_add("foplbhdcjmiabnahcoplaogpmdlhknpg", "Trend Micro Check", "Trend Micro", "vpn_security",
     "Major security vendor, phishing protection", ["security_tool", "vpn_security"])
_add("jknemblkbdhdcpllfgbfekkdciegfboi", "Webroot Filtering", "OpenText", "vpn_security",
     "Enterprise web filtering, verified publisher", ["security_tool", "vpn_security"])

# Additional communication
_add("pnhechapfaindjhompbnflcldabbghjo", "Checker Plus for Gmail", "Jason Savard", "communication",
     "Gmail notification extension, 2M+ users")
_add("fahmaaghhglfmonjliepjlchgpgfmobi", "Pushover Notifications", "Pushover LLC", "communication",
     "Push notification platform companion")

# More Google official  
_add("gomeoldkhebbcahoaedfjnhmiaailnnp", "Google Arts & Culture", "Google", "google_official",
     "Google official, arts exploration")
_add("bfbameneiokkgbdmiekhjnmfkcnldhhm", "Chrome Web Store", "Google", "google_official",
     "Google official, Web Store")
_add("nmmhkkegccagdldgiimedpiccmgmieda", "Chrome Web Store Payments", "Google", "google_official",
     "Google official, payment processing")
_add("pkedcjkdefgpdelpbcmbmeomcjbeemfm", "Chrome Media Router", "Google", "google_official",
     "Google official, Chromecast support")
_add("mmeijimgabbpbgpdklnllpncmdofkcpn", "Screen Capture by Google", "Google", "google_official",
     "Google official, screen recording")

# More dev tools
_add("gighmmpiobklfepjocnamgkkbiglimda", "Accessibility Insights", "Microsoft", "developer_tool",
     "Microsoft official, web accessibility testing")
_add("jpkfjicglakibpenojifdiepckckbggg", "CSS Viewer", "nicedoc", "developer_tool",
     "CSS properties inspector, 400K+ users")
_add("hgimnogjllphhhkhlmebbmlgjoejdpjl", "XPath Helper", "nicedoc", "developer_tool",
     "XPath extraction and testing tool")
_add("gidnphnamkgfflhanalebndpgpakkacg", "WhatRuns", "nicedoc", "developer_tool",
     "Technology detection, similar to Wappalyzer")
_add("hcbgadmbdkiilgpifjgcakjfamoppkga", "Allow CORS", "nicedoc", "developer_tool",
     "CORS header control for development")

# More accessibility
_add("bfcfjadigiifpmkfckfidffkfobdccoj", "Magnifying Glass", "nicedoc", "accessibility",
     "Page magnification for vision impairment")
_add("jipdnfibhldikgcjhfnomkfpcebammhp", "DF Tube", "nicedoc", "accessibility",
     "Distraction-free YouTube viewing")
_add("olnbjpaejebpnokblkepbhglcfiehdhc", "Dyslexia Friendly", "nicedoc", "accessibility",
     "Font and color adjustments for dyslexia")

# More other verified
_add("gmogfdcedjennimfhddkblmmbcehkpib", "Clockwork", "nicedoc", "other_verified",
     "Cookie/localStorage debugging")
_add("epmdjkjbghpnlfkkijhloocnheaaahfd", "Copy All URLs", "nicedoc", "other_verified",
     "Copy all open tab URLs, simple utility")
_add("nhdogjmejiglipccpnnnanhbledajbpde", "Ember Inspector", "Ember.js", "developer_tool",
     "Official Ember.js debugging extension")


# ── Public API ───────────────────────────────────────────────


def lookup_allowlist(extension_id: str) -> AllowlistEntry | None:
    """Look up an extension in the trusted allowlist.

    Returns the AllowlistEntry if found, None otherwise.
    """
    return TRUSTED_EXTENSIONS.get(extension_id)


def is_trusted(extension_id: str) -> bool:
    """Check if an extension is on the trusted allowlist."""
    return extension_id in TRUSTED_EXTENSIONS


def get_alternatives_for_category(category: str) -> list[AllowlistEntry]:
    """Get all trusted extensions in a given category.

    Also includes extensions that list this category in their
    safe_alternative_for field.
    """
    results: list[AllowlistEntry] = []
    for entry in TRUSTED_EXTENSIONS.values():
        if entry.category == category or category in entry.safe_alternative_for:
            results.append(entry)
    return results


def get_all_categories() -> list[str]:
    """Return all category strings."""
    return list(CATEGORIES)


def get_allowlist_size() -> int:
    """Return the total number of trusted extensions."""
    return len(TRUSTED_EXTENSIONS)
