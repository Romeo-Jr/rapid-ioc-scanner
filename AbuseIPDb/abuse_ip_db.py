import requests

class AbuseIPDb:
    def __init__(self, api_key: str, ip: str, delay: int = 5):
        self.api_key = api_key
        self.api_key = api_key
        self.ip = ip
        self.endpoint = "https://api.abuseipdb.com/api/v2/check"
        self.delay = delay
        self.headers = {
            'Key': self.api_key
        }
        self.results = {}
    
    def fetch_data(self) -> dict:
        response = requests.get(self.endpoint, headers=self.headers, params={'ipAddress': self.ip})

        if response.status_code != 200:
            return self.results
        
        data = response.json()
        self.results.update(data)
        return self.results
        
    def get_abuse_conf_score(self) -> int:
        try:
            return self.results.get("data").get("abuseConfidenceScore")
        
        except Exception as err:
            return 404
    
    def get_link(self) -> str:
        try:
            self.results.get("data")
            return f"https://www.abuseipdb.com/check/{self.ip}"
        
        except Exception as err:
            return "Link Not Found"