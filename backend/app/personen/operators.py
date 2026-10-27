"""Country of the company that runs a platform (its legal seat): this is where a request for data would have to go.

Kept short on purpose: only well-known platforms with an undisputed seat. Other sites are placed by a national domain
ending (.de, .fr, .ru, ...) and marked as such; sites with generic endings (.com, .io, ...) stay without a country."""
from __future__ import annotations

OPERATORS: dict[str, str] = {
    # United States
    "github.com": "US", "gist.github.com": "US", "gitlab.com": "US", "reddit.com": "US", "x.com": "US", "twitter.com": "US",
    "instagram.com": "US", "facebook.com": "US", "threads.net": "US", "youtube.com": "US", "twitch.tv": "US",
    "pinterest.com": "US", "tumblr.com": "US", "medium.com": "US", "quora.com": "US", "stackoverflow.com": "US",
    "linkedin.com": "US", "snapchat.com": "US", "discord.com": "US", "steamcommunity.com": "US", "keybase.io": "US",
    "hackerone.com": "US", "bugcrowd.com": "US", "dev.to": "US", "npmjs.com": "US", "pypi.org": "US", "hub.docker.com": "US",
    "patreon.com": "US", "etsy.com": "US", "ebay.com": "US", "imgur.com": "US", "flickr.com": "US", "vimeo.com": "US",
    "behance.net": "US", "dribbble.com": "US", "chess.com": "US", "duolingo.com": "US", "news.ycombinator.com": "US",
    "wordpress.com": "US", "archive.org": "US", "producthunt.com": "US", "slideshare.net": "US", "scribd.com": "US",
    "goodreads.com": "US", "bandcamp.com": "US", "replit.com": "US", "kaggle.com": "US", "codepen.io": "US",
    "gravatar.com": "US", "about.me": "US", "roblox.com": "US", "itch.io": "US", "deviantart.com": "US",
    "hackerrank.com": "US", "huggingface.co": "US", "opensea.io": "US", "sourceforge.net": "US", "imdb.com": "US",
    "hackaday.io": "US", "instructables.com": "US", "yelp.com": "US",
    # Europe
    "soundcloud.com": "DE", "codeberg.org": "DE", "xing.com": "DE", "gutefrage.net": "DE", "mastodon.social": "DE",
    "mastodon.online": "DE", "spotify.com": "SE", "open.spotify.com": "SE", "lichess.org": "FR", "dailymotion.com": "FR",
    "deezer.com": "FR", "last.fm": "GB", "mixcloud.com": "GB", "tryhackme.com": "GB", "hackthebox.com": "GB",
    "app.hackthebox.com": "GB", "ko-fi.com": "GB", "launchpad.net": "GB",
    # Russia
    "vk.com": "RU", "ok.ru": "RU", "livejournal.com": "RU", "yandex.ru": "RU", "yandex.com": "RU",
    # elsewhere
    "t.me": "AE", "telegram.me": "AE", "letterboxd.com": "NZ", "linktr.ee": "AU", "osu.ppy.sh": "AU", "freelancer.com": "AU",
    "fiverr.com": "IL", "wattpad.com": "CA", "myanimelist.net": "JP", "weibo.com": "CN", "bilibili.com": "CN",
    "zhihu.com": "CN", "douban.com": "CN", "gitee.com": "CN", "naver.com": "KR",
}
# national endings that name a country; generic ones (.io, .co, .me, .tv, .ai, .gg, .fm, .ly, .to, .cc, .ws, .sh, ...) are not here
NATIONAL = {
    "de": "DE", "at": "AT", "ch": "CH", "li": "LI", "fr": "FR", "it": "IT", "es": "ES", "pt": "PT", "nl": "NL", "be": "BE",
    "lu": "LU", "pl": "PL", "cz": "CZ", "sk": "SK", "hu": "HU", "ro": "RO", "bg": "BG", "gr": "GR", "se": "SE", "dk": "DK",
    "fi": "FI", "no": "NO", "ee": "EE", "lv": "LV", "lt": "LT", "si": "SI", "hr": "HR", "rs": "RS", "ie": "IE", "uk": "GB",
    "ru": "RU", "ua": "UA", "by": "BY", "kz": "KZ", "tr": "TR", "il": "IL", "ir": "IR", "in": "IN", "jp": "JP", "kr": "KR",
    "cn": "CN", "tw": "TW", "br": "BR", "ar": "AR", "mx": "MX", "cl": "CL", "au": "AU", "nz": "NZ", "za": "ZA", "ca": "CA",
}


def operator(host: str) -> tuple[str | None, str | None]:
    """(country, how) for the host of a profile: how = "list" (known seat) or "tld" (national domain ending)."""
    h = (host or "").lower().strip(".")
    h = h[4:] if h.startswith("www.") else h
    parts = h.split(".")
    for i in range(len(parts) - 1):  # sub.domain.example.com, domain.example.com, example.com
        cc = OPERATORS.get(".".join(parts[i:]))
        if cc:
            return cc, "list"
    cc = NATIONAL.get(parts[-1]) if len(parts) >= 2 else None
    return (cc, "tld") if cc else (None, None)
