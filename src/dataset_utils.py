"""
Dataset Management and Preparation Module for PhishGuard
Handles generation of synthetic demonstration data and importing/cleaning of external datasets.
"""
import random
import pandas as pd
from pathlib import Path
from typing import Tuple, Optional
import config


def generate_synthetic_dataset(output_path: Optional[Path] = None, num_samples: int = 1400) -> pd.DataFrame:
    """
    Generates a high-quality, synthetic demonstration dataset for local development and offline training.
    
    IMPORTANT:
    These URLs are synthetically constructed for offline algorithmic demonstration only.
    They are NOT verified real-world URLs and will NEVER be contacted over the network.
    Labels:
      0 = Likely Legitimate
      1 = Phishing
    """
    if output_path is None:
        output_path = config.SYNTHETIC_DATASET_CSV_PATH

    random.seed(config.RANDOM_SEED)

    # Legitimate base domains and paths
    legit_domains = [
        "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
        "microsoft.com", "apple.com", "amazon.com", "nytimes.com",
        "bbc.com", "coursera.org", "spotify.com", "python.org",
        "scikit-learn.org", "mozilla.org", "cloudflare.com", "cnn.com",
        "nature.com", "nih.gov", "stanford.edu", "mit.edu",
        "harvard.edu", "kaggle.com", "gitlab.com", "medium.com",
        "arxiv.org", "oracle.com", "docker.com", "salesforce.com",
        "linkedin.com", "reddit.com", "quora.com", "bloomberg.com",
        "reuters.com", "adobe.com", "dropbox.com", "slack.com",
        "zoom.us", "cloudflare.com", "w3schools.com", "geeksforgeeks.org"
    ]

    legit_paths = [
        "", "about", "contact", "docs", "api/v1/users", "articles/tech-trends",
        "products/catalog", "category/science", "wiki/Machine_learning",
        "questions/7429184/python-sorting", "projects/repo/blob/main/README.md",
        "en-us/windows/support", "playlist/37i9dQZF1DXcBWIGoYBM5M",
        "news/technology-5829104", "learn/data-structures", "research/paper-1049",
        "download/latest", "events/2026/annual-conference", "blog/engineering-updates",
        "privacy-policy", "terms-of-service", "pricing", "features"
    ]

    legit_queries = [
        "", "?lang=en", "?ref=homepage", "?id=10842", "?tab=overview",
        "?page=2&sort=recent", "?category=security&filter=active",
        "?theme=dark&view=compact", "?session=guest"
    ]

    # Phishing patterns & deceptive elements
    phish_targets = ["paypal", "appleid", "wellsfargo", "bankofamerica", "chase",
                     "netflix", "amazon-security", "microsoft-login", "coinbase",
                     "google-verify", "metamask-auth", "facebook-support", "dhl-tracking"]
    
    phish_keywords = ["login", "verify", "secure", "update", "account", "signin",
                      "validation", "billing", "recovery", "confirm", "unlock", "alert"]
    
    phish_tlds = [".xyz", ".top", ".info", ".online", ".site", ".tk", ".cf", ".club", ".buzz", ".work"]
    
    phish_shorteners = list(config.SHORTENER_DOMAINS)

    urls = []
    labels = []

    half = num_samples // 2

    # 1. Generate Legitimate URLs (Label = 0)
    for _ in range(half):
        domain = random.choice(legit_domains)
        path = random.choice(legit_paths)
        query = random.choice(legit_queries)
        scheme = "https://" if random.random() > 0.05 else "http://"
        
        # Occasional legit subdomain
        if random.random() > 0.7:
            sub = random.choice(["blog", "docs", "app", "dev", "api", "support", "status"])
            domain = f"{sub}.{domain}"
            
        full_url = f"{scheme}{domain}"
        if path:
            full_url += f"/{path}"
        if query:
            full_url += query

        urls.append(full_url)
        labels.append(0)

    # 2. Generate Phishing-style Synthetic URLs (Label = 1)
    for i in range(half):
        archetype = random.choice([
            "ip_address", "brand_hyphen", "multi_subdomain", "at_symbol",
            "shortener", "encoded_keyword", "suspicious_port", "tld_spoof"
        ])

        target = random.choice(phish_targets)
        kw = random.choice(phish_keywords)
        tld = random.choice(phish_tlds)

        if archetype == "ip_address":
            ip = f"{random.randint(11, 215)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            full_url = f"http://{ip}/{target}/{kw}/index.php?user_id={random.randint(10000, 99999)}"

        elif archetype == "brand_hyphen":
            noise = random.randint(10, 99)
            full_url = f"http://{target}-{kw}-{noise}{tld}/account-update/login.html"

        elif archetype == "multi_subdomain":
            full_url = f"http://{target}.{kw}.account.service-security{random.randint(1, 99)}{tld}/webscr?cmd=_login"

        elif archetype == "at_symbol":
            # Deceptive prefix before @
            full_url = f"http://{target}.com@{kw}-portal-auth{tld}/session/auth"

        elif archetype == "shortener":
            shortener = random.choice(phish_shorteners)
            token = f"{kw}_{random.randint(1000, 99999)}"
            full_url = f"http://{shortener}/{token}?auth_token=req_{random.randint(1000, 9999)}"

        elif archetype == "encoded_keyword":
            full_url = f"http://{target}-auth{tld}/%73%65%63%75%72%65/%6C%6F%67%69%6E?verify=true"

        elif archetype == "suspicious_port":
            port = random.choice([8080, 8443, 8888, 9000, 7070])
            full_url = f"http://{target}-portal{tld}:{port}/{kw}/credentials"

        else:  # tld_spoof
            full_url = f"http://{target}.support-billing-center{tld}/auth/{kw}"

        urls.append(full_url)
        labels.append(1)

    df = pd.DataFrame({
        "url": urls,
        "label": labels,
        "dataset_type": ["synthetic_demo"] * len(urls)
    })

    # Deduplicate to prevent identical sample artifacts
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    # Save to disk
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[Dataset] Generated {len(df)} synthetic samples at: {output_path}")

    return df


def load_and_validate_dataset(csv_path: Optional[Path] = None) -> pd.DataFrame:
    """
    Loads, cleans, and validates a phishing dataset from CSV.
    Ensures required columns exist ('url', 'label') and removes duplicates to prevent data leakage.
    """
    if csv_path is None:
        csv_path = config.DATASET_CSV_PATH if config.DATASET_CSV_PATH.exists() else config.SYNTHETIC_DATASET_CSV_PATH

    csv_path = Path(csv_path)
    if not csv_path.exists():
        print(f"[Dataset] Path '{csv_path}' does not exist. Generating synthetic demonstration dataset...")
        return generate_synthetic_dataset(csv_path)

    df = pd.read_csv(csv_path)

    # Validate columns
    required_cols = {"url", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"Dataset at {csv_path} is missing required columns: {required_cols - set(df.columns)}")

    # Clean data
    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)

    # Filter out empty URLs and invalid labels
    df = df[df["url"].str.len() > 0]
    df = df[df["label"].isin([0, 1])]

    # Deduplicate to prevent data leakage between train and test sets
    initial_len = len(df)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    deduped_count = initial_len - len(df)
    if deduped_count > 0:
        print(f"[Dataset] Removed {deduped_count} duplicate URLs to prevent data leakage.")

    print(f"[Dataset] Loaded {len(df)} samples ({df['label'].value_counts().to_dict()}) from {csv_path}")
    return df


def import_external_dataset(input_csv_path: str, output_csv_path: Optional[Path] = None,
                            url_col: str = "url", label_col: str = "label") -> pd.DataFrame:
    """
    Utility workflow to import and standardize a real-world phishing dataset.
    Converts arbitrary column names to standard 'url' and 'label', removes duplicates,
    and saves to destination.
    """
    if output_csv_path is None:
        output_csv_path = config.DATASET_CSV_PATH

    raw_df = pd.read_csv(input_csv_path)
    if url_col not in raw_df.columns or label_col not in raw_df.columns:
        raise ValueError(f"Columns '{url_col}' or '{label_col}' not found in {input_csv_path}")

    standardized = pd.DataFrame({
        "url": raw_df[url_col].astype(str).str.strip(),
        "label": raw_df[label_col].astype(int),
        "dataset_type": ["external_imported"] * len(raw_df)
    })

    standardized = standardized.dropna().drop_duplicates(subset=["url"]).reset_index(drop=True)
    output_path = Path(output_csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    standardized.to_csv(output_path, index=False)
    print(f"[Dataset] Successfully imported {len(standardized)} samples to {output_path}")
    return standardized
