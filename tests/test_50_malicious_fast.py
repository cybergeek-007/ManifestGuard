import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tests.test_100_extensions import TestExtension
from backend.scanner import choose_verdict, compute_anomaly_score

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
    "dknlfmjaanfblgfdfebhijalfmhmjjjo", # The Great Suspender
    "biihmcacfjcankndbnogbbhkgimplicl", # Fake ChatGPT
]

def run_fast_scan():
    print("=" * 80)
    print(f" FAST SCAN RESULTS FOR {len(malicious_extensions)} MALICIOUS EXTENSIONS")
    print("=" * 80)
    
    verdicts = {"known_malicious": 0, "suspicious": 0, "moderate_risk": 0, "trusted": 0, "low_concern": 0}
    
    for ext_id in malicious_extensions:
        ext_data = TestExtension(
            id=ext_id,
            name=f"Malicious Ext {ext_id[:6]}",
            description="Fake description",
            permissions=["<all_urls>", "webRequest", "cookies", "tabs"],
            host_permissions=["*://*/*"],
            expected_verdict="known_malicious"
        )
        
        base_anomaly = compute_anomaly_score(ext_data, 1, "unavailable_or_removed")
        base_anomaly += 30 # Intel boost
        
        verdict = choose_verdict(
            reach_score=100,
            anomaly_score=base_anomaly,
            intel_count=1,
            store_status="unavailable_or_removed",
            reputation_data={"score": 10},
            is_allowlisted=False,
            is_known_malicious=True
        )
        
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        status_symbol = "🔴" if verdict in ["known_malicious", "suspicious", "moderate_risk"] else "🟢"
        
        print(f"{status_symbol} {ext_id} -> {verdict.upper()} (Score: {base_anomaly})")
        
    print("-" * 80)
    print("VERDICT SUMMARY:")
    for v, count in verdicts.items():
        if count > 0:
            print(f"  {v}: {count}")

if __name__ == "__main__":
    run_fast_scan()
