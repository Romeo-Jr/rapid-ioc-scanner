import requests
from .utils import encode_url_to_base64

class VirusTotal:

    def __init__(self, api_key: str, ioc: str, ioc_type: str, delay: int = 5):
        self.api_key = api_key
        self.ioc = ioc
        self.ioc_type = ioc_type
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {"x-apikey": self.api_key}
        self.delay = delay
        self.results = {}

    def fetch_data(self) -> dict:
        ioc_url = self.base_url
        ioc_type_mapping = {
            "URL": f"urls/{encode_url_to_base64(self.ioc)}",
            "IP": f"ip_addresses/{self.ioc}",
            "Domain": f"domains/{self.ioc}",
            "Hash": f"files/{self.ioc}"
        }
        
        ioc_url += ioc_type_mapping.get(self.ioc_type, "")
        response = requests.get(ioc_url, headers=self.headers)

        if response.status_code == 200:
            data = response.json()
            self.results.update(data)
            return self.results
        
        else:
            return {"error": f"Failed to retrieve data (Status: {response.status_code})"}

    def get_community_score(self) -> int:
        try:
            data = self.results.get("data")
            analysis_results = data.get("attributes").get("last_analysis_results")

            flagged_count = sum(
                1 for result in analysis_results.values() if result["result"] not in [None, "clean", "unrated"]
            )

            return flagged_count
        
        except Exception as err:
            return 404
    
    def get_link(self) -> str:
        try:
            self.results.get("data")
            BASE_URL = "https://www.virustotal.com/gui/"

            ioc_mapping = {
                "IP": f"{BASE_URL}ip-address/{self.ioc}",
                "Hash": f"{BASE_URL}file/{self.ioc}",
                "Domain": f"{BASE_URL}domain/{self.ioc}",
                "URL": f"{BASE_URL}url/{encode_url_to_base64(self.ioc)}"
            }

            return ioc_mapping.get(self.ioc_type)
        
        except Exception as err:
            return "Link not Found"
        