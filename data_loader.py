import pandas as pd
import requests
import io
import os
import zipfile

class DataLoader:
    def __init__(self):
        self.data = []

    @staticmethod
    def _clean_url_frame(df):
        if df.empty:
            return df

        df = df[['url', 'label']].dropna()
        df['url'] = df['url'].astype(str).str.strip()
        df = df[df['url'] != '']
        df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
        df = df[df['label'].isin([0, 1])]
        return df.drop_duplicates(subset=['url'])

    def fetch_phishtank(self):
        print("Fetching PhishTank data...")
        try:
            # PhishTank offers a CSV feed (requires API key or manual download usually, 
            # using a placeholder URL for structure)
            url = "http://data.phishtank.com/data/online-valid.csv"
            headers = {'User-Agent': 'PhishingDetector/1.0'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                df = pd.read_csv(io.StringIO(response.text))
                df = df[['url']]
                df['label'] = 1
                self.data.append(df)
        except Exception as e:
            print(f"PhishTank fetch skipped: {e}")

    def fetch_openphish(self):
        print("Fetching OpenPhish data...")
        try:
            url = "https://openphish.com/feed.txt"
            response = requests.get(url, timeout=10, headers={'User-Agent': 'PhishingDetector/1.0'})
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                df = pd.DataFrame(urls, columns=['url'])
                df['label'] = 1 # 1 = Malicious
                self.data.append(df)
        except Exception as e:
            print(f"OpenPhish fetch error: {e}")

    def fetch_urlhaus(self):
        print("Fetching URLhaus data...")
        try:
            url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
            response = requests.get(url, timeout=10, headers={'User-Agent': 'PhishingDetector/1.0'})
            if response.status_code == 200:
                # Skip comments starting with #
                df = pd.read_csv(io.StringIO(response.text), comment='#', header=None)
                # Column 2 (index 2) is usually the URL in URLhaus recent CSV
                df = df.iloc[:, [2]]
                df.columns = ['url']
                df['label'] = 1
                self.data.append(df)
        except Exception as e:
            print(f"URLhaus fetch error: {e}")

    def fetch_benign_tranco(self):
        print("Fetching Tranco (Benign) data...")
        try:
            # Check for extracted CSV first (User placed file)
            if os.path.exists('top-1m.csv'):
                print("Using local top-1m.csv")
                df = pd.read_csv('top-1m.csv', header=None, names=['rank', 'domain'], nrows=3000)
                
                urls = []
                for domain in df['domain']:
                    urls.append(f"https://{domain}")
                    urls.append(f"http://{domain}")
                
                df_final = pd.DataFrame(urls, columns=['url'])
                df_final['label'] = 0
                self.data.append(df_final)
                print(f"Loaded {len(df_final)} benign domains from Tranco.")
                return

            # Check for local file first
            if os.path.exists('top-1m.csv.zip'):
                print("Using local top-1m.csv.zip")
                z_obj = zipfile.ZipFile('top-1m.csv.zip')
            else:
                # Download the top 1 million domains list (approx 6MB)
                url = "https://tranco-list.eu/top-1m.csv.zip"
                response = requests.get(url, stream=True, timeout=15, headers={'User-Agent': 'PhishingDetector/1.0'})
                
                if response.status_code == 200:
                    z_obj = zipfile.ZipFile(io.BytesIO(response.content))
                else:
                    raise Exception("Failed to download Tranco list")

            with z_obj as z:
                with z.open('top-1m.csv') as f:
                    # Read top 3000 domains to balance the dataset
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=3000)
                    
                    # Create URL variations (http/https) to make the model robust
                    urls = []
                    for domain in df['domain']:
                        urls.append(f"https://{domain}")
                        urls.append(f"http://{domain}")
                    
                    df_final = pd.DataFrame(urls, columns=['url'])
                    df_final['label'] = 0
                    self.data.append(df_final)
                    print(f"Loaded {len(df_final)} benign domains from Tranco.")
        except Exception as e:
            print(f"Tranco fetch error: {e}")
            # Fallback to a small list if download fails
            top_domains = ["google.com", "apple.com", "microsoft.com", "amazon.com", "facebook.com"]
            urls = [f"https://{d}" for d in top_domains] + [f"http://{d}" for d in top_domains]
            self.data.append(pd.DataFrame(urls, columns=['url']).assign(label=0))

    def get_data(self):
        # Fetch real data from sources
        self.fetch_phishtank()
        self.fetch_openphish()
        self.fetch_urlhaus()
        self.fetch_benign_tranco()
        
        # Combine scraped data if available
        if self.data:
            cleaned_frames = [self._clean_url_frame(df_item) for df_item in self.data if not df_item.empty]
            if cleaned_frames:
                df_full = pd.concat(cleaned_frames, ignore_index=True)
            else:
                df_full = pd.DataFrame(columns=['url', 'label'])
            
            # Balance classes to prevent bias
            malicious = df_full[df_full['label'] == 1]
            benign = df_full[df_full['label'] == 0]
            
            if not malicious.empty and not benign.empty:
                # Use equal number of samples for both classes
                n_samples = min(len(malicious), len(benign), 2000)
                df_scraped = pd.concat([
                    malicious.sample(n_samples, random_state=42),
                    benign.sample(n_samples, random_state=42)
                ]).sample(frac=1, random_state=42).reset_index(drop=True)
            else:
                df_scraped = df_full
                if len(df_scraped) > 2000:
                    df_scraped = df_scraped.sample(2000, random_state=42)
        else:
            df_scraped = pd.DataFrame(columns=['url', 'label'])

        # Use scraped data
        df = df_scraped
        
        # Integrate feedback data (Self-Learning)
        if os.path.exists('feedback_data.csv'):
            print("Loading feedback data...")
            df_feedback = pd.read_csv('feedback_data.csv')
            df_feedback = self._clean_url_frame(df_feedback)
            df = pd.concat([df, df_feedback], ignore_index=True)

        # Last-pass cleanup and dedupe to avoid contradictory duplicates.
        df = self._clean_url_frame(df)
        if not df.empty:
            df = df.groupby('url', as_index=False)['label'].max()
            
        return df
