import ipaddress
import re
import urllib.request
import urllib.parse
from bs4 import BeautifulSoup
import socket
import requests
from sympy import Domain
import whois
from datetime import date
from urllib.parse import urlparse
from googlesearch import search

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.features = []
        self.domain = ""
        self.whois_response = None  # Initialize as None
        self.urlparse = None  # Initialize as None
        self.response = None  # Initialize as None
        self.soup = None  # Initialize as None
        self.whois_data = None  # Change the name of the property
        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')  # Fixed variable name
        except Exception as e:
            print(e)
            # Handle exceptions gracefully

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(e)
            # Handle exceptions gracefully

        try:
            # ...
            self.whois_data = whois.whois(self.domain)  # Update the property name
        except Exception as e:
            print(e)

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2. longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3. shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4. Symbol@
    def symbol(self):
        if re.findall("@", self.url):
            return -1
        return 1

    # 5. Redirecting//
    def redirecting(self):
        if self.url.rfind('//') > 6:
            return -1
        return 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7. SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_data.expiration_date
            creation_date = self.whois_data.creation_date
            try:
                if len(expiration_date):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head_link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head_link['href'])]
                    if self.url in head_link['href'] or len(dots) == 1 or Domain in head_link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            i, success = 0, 0
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif (percentage >= 22.0) and (percentage < 61.0):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                        self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif (percentage >= 31.0) and (percentage < 67.0):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0

            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif (percentage >= 17.0) and (percentage < 81.0):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            i, success = 0, 0

            for form in self.soup.find_all('form', action=True):
                if form['action'] == "about:blank":
                    success = success + 1
                elif self.url in form['action'] or self.domain in form['action']:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 13.0:
                    return 1
                elif (percentage >= 13.0) and (percentage < 81.0):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if "mailto:" in self.url:
                return -1
            return 1
        except:
            return 1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.url.startswith("http") and len(self.url) < 50:
                return 1
            return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(urllib.parse.urlparse(self.url).path) != len(
                    urllib.parse.urlparse(self.url).netloc):
                return -1
            return 1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if 'onmouseover' in self.soup.prettify():
                return -1
            return 1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if "event.button==2" in self.soup.prettify():
                return -1
            return 1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if "window.open" in self.soup.prettify():
                return -1
            return 1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if "<iframe" in self.soup.prettify():
                return -1
            return 1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            current_date = date.today()
            age = (current_date.year - creation_date.year) * 12 + current_date.month - creation_date.month
            if age >= 6:
                return -1
            return 1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            domain = whois.whois(self.domain)
            if domain.status is None:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            ip_address = socket.gethostbyname(self.domain)
            ip_address = ipaddress.ip_address(ip_address)
            if ip_address.is_global:
                return -1
            return 1
        except:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            rank_checker_response = requests.get(f'https://www.rank-checker.org/?p={self.domain}')
            rank_checker_response = BeautifulSoup(rank_checker_response.text, 'html.parser')
            if "is not recognized by Google" in rank_checker_response.text:
                return -1
            elif "has no global rank" in rank_checker_response.text:
                return 0
            else:
                return 1
        except:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            search_results = list(search(self.url, num=1, stop=1, pause=2))
            for result in search_results:
                if self.url in result:
                    return 1
            return -1
        except:
            return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            i, success = 0, 0
            for a in self.soup.find_all('a', href=True):
                if self.url in a['href']:
                    success = success + 1
                i = i + 1

            for link in self.soup.find_all('link', href=True):
                if self.url in link['href']:
                    success = success + 1
                i = i + 1

            for script in self.soup.find_all('script', src=True):
                if self.url in script['src']:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif (percentage >= 31.0) and (percentage < 80.0):
                    return 0
                else:
                    return -1
            except:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            if "Domain Name: " in self.whois_response.text:
                return 1
            return -1
        except:
            return -1


    def getFeaturesList(self):
        return self.features





