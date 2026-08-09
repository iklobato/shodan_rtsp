from pydantic import BaseModel, FilePath


class ShodanConfig(BaseModel):
    shodan_key: str


class CheckersConfig(BaseModel):
    wordlist_users: FilePath
    wordlist_passwords: FilePath
    wordlist_rtsp_urls: FilePath
    randomize: bool = False


class NmapConfig(BaseModel):
    ip_range: str
