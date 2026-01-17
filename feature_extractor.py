
import re
from urllib.parse import urlparse
import socket
import whois
import requests
from datetime import datetime
import time

def extract_features(url):
    features = {}

    # 1. having_IP_Address
    try:
        ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
        features['having_IP_Address'] = -1 if ip else 1
    except:
        features['having_IP_Address'] = 1

    # 2. URL_Length
    if len(url) < 54:
        features['URL_Length'] = 1
    elif 54 <= len(url) <= 75:
        features['URL_Length'] = 0
    else:
        features['URL_Length'] = -1

    # 3. Shortining_Service
    short_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                     r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                     r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                     r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                     r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                     r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                     r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                     r"tr\.im|link\.zip\.net"
    if re.search(short_services, url, flags=re.IGNORECASE):
        features['Shortining_Service'] = -1
    else:
        features['Shortining_Service'] = 1

    # 4. having_At_Symbol
    if '@' in url:
        features['having_At_Symbol'] = -1
    else:
        features['having_At_Symbol'] = 1

    # 5. double_slash_redirecting
    # The position of the last occurrence of // in the URL
    if url.rfind('//') > 7:
        features['double_slash_redirecting'] = -1
    else:
        features['double_slash_redirecting'] = 1

    # 6. Prefix_Suffix
    parsed = urlparse(url)
    if '-' in parsed.netloc:
        features['Prefix_Suffix'] = -1
    else:
        features['Prefix_Suffix'] = 1

    # 7. having_Sub_Domain
    # Remove www
    domain = parsed.netloc.replace("www.", "")
    dots = domain.count('.')
    if dots == 1:
        features['having_Sub_Domain'] = 1
    elif dots == 2:
        features['having_Sub_Domain'] = 0
    else:
        features['having_Sub_Domain'] = -1

    # 8. SSLfinal_State (Heuristic: https presence and issuer checking is hard without simpler API)
    # Simplified: Check for https
    if parsed.scheme == 'https':
        features['SSLfinal_State'] = 1 # Assuming trusted for now
    else:
        features['SSLfinal_State'] = -1

    # 9. Domain_registeration_length
    # Needs WHOIS
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        if expiration_date and creation_date:
            age = (expiration_date - creation_date).days
            if age / 365 >= 1:
                features['Domain_registeration_length'] = 1
            else:
                features['Domain_registeration_length'] = -1
        else:
             features['Domain_registeration_length'] = -1
    except:
        features['Domain_registeration_length'] = -1

    # 10. Favicon
    # Hard to check without crawling. Assume 1 (legit) if manual input not provided.
    features['Favicon'] = 1 

    # 11. port
    try:
        # Standard ports 80, 443 are fine. Others might be suspicious.
        if parsed.port and parsed.port not in [80, 443]:
             features['port'] = -1
        else:
             features['port'] = 1
    except:
        features['port'] = 1

    # 12. HTTPS_token
    # Domain contains 'https'
    if 'https' in domain:
        features['HTTPS_token'] = -1
    else:
        features['HTTPS_token'] = 1

    # 13. Request_URL (External objects)
    # Hard to compute. Default 1
    features['Request_URL'] = 1

    # 14. URL_of_Anchor
    # Hard to compute. Default 0
    features['URL_of_Anchor'] = 0

    # 15. Links_in_tags
    # Hard to compute. Default 0
    features['Links_in_tags'] = 0

    # 16. SFH
    # Server Form Handler. Default 1
    features['SFH'] = 1

    # 17. Submitting_to_email
    # "mailto:" in source code. Default 1 (not found)
    features['Submitting_to_email'] = 1

    # 18. Abnormal_URL
    # if hostname is not in URL
    if domain not in url:
         features['Abnormal_URL'] = -1
    else:
         features['Abnormal_URL'] = 1

    # 19. Redirect
    # Default 0
    features['Redirect'] = 0

    # 20. on_mouseover
    # status bar change? Default 1
    features['on_mouseover'] = 1

    # 21. RightClick
    # Disabled? Default 1
    features['RightClick'] = 1

    # 22. popUpWidnow
    # Default 1
    features['popUpWidnow'] = 1

    # 23. Iframe
    # Default 1
    features['Iframe'] = 1

    # 24. age_of_domain
    # Used WHOIS above
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            today = datetime.now()
            age_months = (today - creation_date).days / 30
            if age_months >= 6:
                features['age_of_domain'] = 1
            else:
                 features['age_of_domain'] = -1
        else:
             features['age_of_domain'] = -1
    except:
        features['age_of_domain'] = -1

    # 25. DNSRecord
    features['DNSRecord'] = 1 # Assuming it exists if we reached here

    # 26. web_traffic
    # Alexa rank API needed. Placeholder.
    features['web_traffic'] = 1

    # 27. Page_Rank
    # Placeholder
    features['Page_Rank'] = 1

    # 28. Google_Index
    features['Google_Index'] = 1

    # 29. Links_pointing_to_page
    features['Links_pointing_to_page'] = 0

    # 30. Statistical_report
    features['Statistical_report'] = 1
    
    return features
