Dark Spectre is a Tor-powered keyword hunter for darknet & clearnet URLs.
It recursively follows links ONLY along branches where the keyword/phrase keeps re-appearing.
Now supports regex searches and a JSON report with depth and parent chains.

Dark Spectre — Tor Keyword Hunter Ops Cheat Sheet

> python3 dark_spectre.py URL_LIST PHRASE [options]
URL_LIST → file with one URL per line (.onion or clearnet)
