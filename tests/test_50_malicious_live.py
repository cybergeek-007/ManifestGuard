import asyncio
import httpx
import json

malicious_extensions = [
    "aaakfiobbojanlacpbeejjimehmpoffh", "aacfibelemnkkbkelbhdbfhokeemfaho",
    "aaddmojoibcjdlghmeeeenlgenaogcif", "aadmpgppfacognoeobmheghfiibdplcf",
    "aadnmeanpbokjjahcnikajejglihibpd", "aaeohfpkhojgdhocdfpkdaffbehjbmmd",
    "aafibkjcplagpjkhkeamkpaellnglepe", "aahjpoblnboigndgjiijcnbahniepnbo",
    "aaiolimgbncdaldgbbjkidiijidchhjo", "aajdkangkldmljmoaoehmbnchdjkgojk",
    "aapdalkmclfaahehnmicbglkohkldhne", "abbngaojehjekanfdipifimgmppiojpl",
    "abclkepfnkmfkhohoogobbekdcdghaoi", "abekedpmkgndeflcidpkkddapnjnocjp",
    "abgbjkemnkollcpimnfnmoakjedaenfd", "abgfholnofpihncfdmombecmohpkojdb",
    "abghmipjfclfpgmmelbgolfgmhnigbma", "abgpfcaflplbnjkpeoimjchehdhakped",
    "abigbbblmfhbgbjjdolageghdkdibeap", "abjbfhcehjndcpbiiagdnlfolkbfblpb",
    "abkebhncjihnoblbkcmhogfdpdmdklhg", "abkolnpebgghiglkkdjcgjgbpnddmfmp",
    "abpcbpoghgmfjkkdoeknbldhkklpcmfn", "abpppenajdmdganodlmoeocldojbbjgp",
    "acaeafediijmccnjlokgcdiojiljfpbe", "acbcnnccgmpbkoeblinmoadogmmgodoo",
    "acbiaofoeebeinacmcknopaikmecdehl", "acchdggcflgidjdcnhnnkfengdcmldae",
    "acdfdofofabmipgcolilkfhnpoclgpdd", "acejnkocmhhdeepejldlchcpcokmomia",
    "acfjniffcmahollkfpmbafogeknigieg", "achcinfieogfidhjekdbbmapmffifchl",
    "aciamgifeoagmcojlibbdhoabolgdopo", "acigamgkhbdgmhjgblcliidogdlnbfff",
    "aciipkgmbljbcokcnhjbjdhilpngemnj", "aciloeifdphkogbpagikkpiecbjkmedn",
    "acjkfmnbignocfakclealmabijofkaba", "ackibjdmcolfjjdpabnfjipaolkkpagp",
    "acmfnomgphggonodopogfbmkneepfgnh", "acmgemnaochmalgkipbamjddcplkdmjm",
    "acmiibcdcmaghndcahglamnhnlmcmlng", "acmnokigkgihogfbeooklgemindnbine",
    "acncpfocelnijeegfclfigffjgancfod", "acogeoajdpgplfhidldckbjkkpgeebod",
    "acojldicjlifbkkfaijnomogffamiadi", "addnfehdcokmboamjapbiihagbppejnb",
    "addpbbembilhmnkjpenjgcgmihlcofja", "adfjcmhegakkhojnallobfjbhenbkopj",
    "adjcpjpdmmlcledcenjinjnhnjcnciih", "adjiklnjodbiaioggfpbpkhbfcnhgkfe",
    # Add a few known from intel registry
    "dknlfmjaanfblgfdfebhijalfmhmjjjo", # The Great Suspender
    "biihmcacfjcankndbnogbbhkgimplicl", # Fake ChatGPT
]

async def run_scan():
    print(f"Submitting scan request for {len(malicious_extensions)} malicious extensions...")
    
    # We simulate what the companion extension sends.
    payload = {
        "extensions": [
            {
                "id": ext_id,
                "name": f"Malicious Ext {ext_id[:6]}",
                "version": "1.0.0",
                "description": "A simulated malicious extension payload.",
                "permissions": ["<all_urls>", "webRequest", "cookies", "tabs"],
                "hostPermissions": ["*://*/*"],
                "enabled": True,
                "installType": "normal"
            } for ext_id in malicious_extensions[:20]
        ],
        "enableAi": False
    }

    async with httpx.AsyncClient(timeout=180.0) as client:
        try:
            resp = await client.post("http://127.0.0.1:8000/api/scans/online", json=payload)
            resp.raise_for_status()
            scan_data = resp.json()
            
            print("=" * 80)
            print(" SCAN RESULTS FOR 52 MALICIOUS EXTENSIONS")
            print("=" * 80)
            print(f"Scan ID: {scan_data['scan_id']}")
            print(f"Report URL: http://127.0.0.1:8000/api/scans/{scan_data['scan_id']}/reports/html")
            print("-" * 80)
            
            verdicts = {"known_malicious": 0, "suspicious": 0, "moderate_risk": 0, "trusted": 0, "low_concern": 0}
            
            for f in scan_data['findings']:
                verdict = f['verdict']
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
                status_symbol = "🔴" if verdict in ["known_malicious", "suspicious", "moderate_risk"] else "🟢"
                
                print(f"{status_symbol} {f['id']} -> {verdict.upper()} (CWS Status: {f['store_status']})")
                
            print("-" * 80)
            print("VERDICT SUMMARY:")
            for v, count in verdicts.items():
                print(f"  {v}: {count}")
                
        except Exception as e:
            print(f"Error calling API: {e}")

if __name__ == "__main__":
    asyncio.run(run_scan())
