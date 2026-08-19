import urllib.parse
import tldextract

def parse_and_clean_url(raw_url: str) -> dict:
    parsed = urllib.parse.urlparse(raw_url if raw_url.startswith(('http://', 'https://')) else f'http://{raw_url}')
    extracted = tldextract.extract(parsed.netloc)
    
    return {
        "original_url": raw_url,
        "scheme": parsed.scheme,
        "domain": extracted.domain,
        "subdomain": extracted.subdomain,
        "suffix": extracted.suffix,
        "full_domain": f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain,
        "path": parsed.path
    }