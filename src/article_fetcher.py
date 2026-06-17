from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import requests
from bs4 import BeautifulSoup


@dataclass
class Article:
    url: str
    title: str
    text: str
    html: str


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)


def clean_text(text: str) -> str:
    lines = [line.strip() for line in text.splitlines()]
    non_empty = [line for line in lines if line]
    return "\n".join(non_empty)


def extract_title(soup: BeautifulSoup, fallback_url: str) -> str:
    if soup.title and soup.title.string:
        return soup.title.string.strip()

    og_title = soup.find("meta", attrs={"property": "og:title"})
    if og_title and og_title.get("content"):
        return og_title["content"].strip()

    h1 = soup.find("h1")
    if h1:
        return h1.get_text(" ", strip=True)

    return fallback_url


def extract_main_text(soup: BeautifulSoup) -> str:
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    main_candidates = [
        soup.find("article"),
        soup.find("main"),
        soup.find("div", class_="article"),
        soup.find("div", class_="post"),
        soup.find("div", class_="entry-content"),
        soup.find("div", id="content"),
    ]

    container = next((c for c in main_candidates if c is not None), soup.body or soup)

    text = container.get_text("\n", strip=True)
    return clean_text(text)


def fetch_article(url: str, timeout: int = 20) -> Article:
    response = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
    )
    response.raise_for_status()

    html = response.text
    soup = BeautifulSoup(html, "html.parser")

    title = extract_title(soup, url)
    text = extract_main_text(soup)

    if not text:
        raise ValueError("Could not extract any text from the article")

    return Article(
        url=url,
        title=title,
        text=text,
        html=html,
    )