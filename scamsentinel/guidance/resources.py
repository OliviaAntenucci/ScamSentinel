"""'Learn more' links for an analysis (architecture.md §22).

Picks, from data/resources.yaml only:
- scam_type: articles about the kind of scam (FTC, IRS, USPIS), by the named scenario,
  else the claimed brand's category, else the default. Only for flagged results.
- official_help: the impersonated organization's own help pages, scenario-specific ones
  first. Also on a likely-legitimate result, where they help verify the message.

No URL here ever comes from the analyzed content. Load-time checks keep articles on
trusted consumer-protection domains and help pages on the brand's official domains.
"""

from __future__ import annotations

from collections.abc import Sequence

from scamsentinel.data import Brand, ResourcesFile, url_on_domains
from scamsentinel.models import Resource, Scenario, Verdict

MAX_SCAM_TYPE = 2
MAX_OFFICIAL_HELP = 2


class ReadingList:
    def __init__(
        self,
        resources: ResourcesFile,
        brands: Sequence[Brand],
        scenario_ids: Sequence[str] = (),
    ) -> None:
        official = {b.name: b.official_domains for b in brands}
        categories = {b.category for b in brands}
        unknown_brands = set(resources.official_help) - set(official)
        if unknown_brands:
            raise ValueError(f"resources.yaml names unknown brands: {sorted(unknown_brands)}")
        for brand, pages in resources.official_help.items():
            for page in pages:
                if not url_on_domains(page.url, official[brand]):
                    raise ValueError(f"{brand} help page isn't on its official domains: {page.url}")
        unknown_categories = set(resources.scam_types.categories) - categories
        if unknown_categories:
            raise ValueError(
                f"resources.yaml uses unknown categories: {sorted(unknown_categories)}"
            )
        if scenario_ids:
            known = set(scenario_ids)
            used = set(resources.scam_types.scenarios) | {
                s for pages in resources.official_help.values() for p in pages for s in p.scenarios
            }
            if used - known:
                raise ValueError(f"resources.yaml uses unknown scenarios: {sorted(used - known)}")
        self._resources = resources

    def build(
        self,
        *,
        verdict: Verdict,
        entity: str | None,
        category: str | None,
        scenario: Scenario | None,
    ) -> list[Resource]:
        links: list[Resource] = []
        if verdict != Verdict.LIKELY_LEGITIMATE:
            links += self._scam_type(category, scenario)
        if entity:
            links += self._official_help(entity, scenario)
        seen: set[str] = set()
        unique = []
        for link in links:
            if link.url not in seen:
                seen.add(link.url)
                unique.append(link)
        return unique

    def _scam_type(self, category: str | None, scenario: Scenario | None) -> list[Resource]:
        types = self._resources.scam_types
        ids = (
            (scenario and types.scenarios.get(scenario.id))
            or (category and types.categories.get(category))
            or types.default
        )
        return [
            Resource(
                kind="scam_type",
                title=a.title,
                publisher=a.publisher,
                url=a.url,
                last_reviewed=a.reviewed,
            )
            for a in (self._resources.articles[i] for i in ids[:MAX_SCAM_TYPE])
        ]

    def _official_help(self, entity: str, scenario: Scenario | None) -> list[Resource]:
        pages = self._resources.official_help.get(entity, [])
        specific = [p for p in pages if scenario and scenario.id in p.scenarios]
        general = [p for p in pages if not p.scenarios]
        return [
            Resource(
                kind="official_help",
                title=p.title,
                publisher=entity,
                url=p.url,
                last_reviewed=p.reviewed,
            )
            for p in [*specific, *general][:MAX_OFFICIAL_HELP]
        ]
