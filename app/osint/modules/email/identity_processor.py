"""
============================================================
TraceLens Email Identity Intelligence Post-Processor
============================================================

Aggregates raw collector outputs into unified identity intelligence data structures:
- Identity Summary & Confidence Scoring with Explanations
- Merged Public Avatar Cards
- Discovered Evidence Items with Provider Attribution
- Real Username Extraction (ignoring generated email handles)
- Username Handoff Candidates
- Identity Discovery Timeline
- Planned / Future Providers

Author:
    TraceLens
"""

from typing import Any
from app.osint.modules.email.identity_models import (
    DiscoveredUsername,
    UsernameCandidate,
    EvidenceItem,
    UnifiedAvatarCard,
    IdentitySummary,
    TimelineStep,
)


PLANNED_PROVIDERS = [
    {"provider": "Adobe", "category": "Creative & Cloud", "status": "Support Planned", "description": "Enterprise & Creative Cloud presence check planned."},
    {"provider": "Spotify", "category": "Media & Streaming", "status": "Support Planned", "description": "Public listening profile & account lookup planned."},
    {"provider": "Discord", "category": "Chat & Community", "status": "Support Planned", "description": "Discord user search & bot lookup planned."},
    {"provider": "Steam", "category": "Gaming Platform", "status": "Support Planned", "description": "Steam Community profile & vanity URL search planned."},
    {"provider": "Dropbox", "category": "Cloud Storage", "status": "Support Planned", "description": "Dropbox shared folder & profile check planned."},
    {"provider": "LinkedIn", "category": "Professional Network", "status": "Support Planned", "description": "Professional identity correlation planned."},
    {"provider": "Canva", "category": "Design & Publishing", "status": "Support Planned", "description": "Public design portfolio lookup planned."},
]


def process_email_identity(
    collector_results: list[dict[str, Any]], target_email: str
) -> dict[str, Any]:
    """
    Main identity intelligence post-processor.

    Args:
        collector_results: Raw list of results dictionaries from all email collectors.
        target_email: The target email address string.

    Returns:
        Dictionary containing identity_summary, evidence, public_avatar,
        discovered_usernames, username_candidates, timeline, and future_providers.
    """
    email_local_part = target_email.split("@")[0].lower() if "@" in target_email else ""

    profiles_found: list[dict[str, Any]] = []
    avatars_found: list[dict[str, Any]] = []
    discovered_usernames: list[dict[str, str]] = []
    username_candidates: list[dict[str, str]] = []
    evidence_items: list[dict[str, str]] = []
    seen_usernames_set: set[tuple[str, str]] = set()

    # 1. Collect findings from all collectors
    for col in collector_results:
        col_name = col.get("collector")

        # --- Account Presence Collector ---
        if col_name in ("Account Presence Collector", "Account Presence"):
            for res in col.get("results", []):
                if res.get("status") == "REGISTERED":
                    prov = res.get("provider", "Unknown")
                    uname = res.get("username")
                    dname = res.get("display_name")
                    avatar = res.get("avatar_url")
                    p_url = res.get("profile_url")
                    loc = res.get("location")
                    site = res.get("website")
                    bio = res.get("bio")
                    exec_time = res.get("metadata", {}).get("execution_time_ms")

                    profile_entry = {
                        "provider": prov,
                        "status": "REGISTERED",
                        "username": uname,
                        "display_name": dname,
                        "avatar_url": avatar,
                        "profile_url": p_url,
                        "location": loc,
                        "website": site,
                        "bio": bio,
                        "execution_time_ms": exec_time,
                    }
                    profiles_found.append(profile_entry)

                    # Extract username if present and not matching email generation rules
                    if uname and (prov, uname.lower()) not in seen_usernames_set:
                        seen_usernames_set.add((prov, uname.lower()))
                        discovered_usernames.append(
                            DiscoveredUsername(provider=prov, username=uname).to_dict()
                        )
                        username_candidates.append(
                            UsernameCandidate(provider=prov, username=uname, confidence="High").to_dict()
                        )

                    # Extract evidence
                    if avatar:
                        evidence_items.append(EvidenceItem("Public Avatar", avatar, prov).to_dict())
                    if dname:
                        evidence_items.append(EvidenceItem("Public Display Name", dname, prov).to_dict())
                    if uname:
                        evidence_items.append(EvidenceItem("Public Username", f"@{uname}", prov).to_dict())
                    if loc:
                        evidence_items.append(EvidenceItem("Public Location", loc, prov).to_dict())
                    if site:
                        evidence_items.append(EvidenceItem("Public Website", site, prov).to_dict())
                    if p_url:
                        evidence_items.append(EvidenceItem("Public Profile URL", p_url, prov).to_dict())

                    if avatar:
                        avatars_found.append({
                            "provider": prov,
                            "avatar_url": avatar,
                            "display_name": dname,
                            "username": uname,
                            "location": loc,
                            "website": site,
                            "profile_url": p_url,
                        })

        # --- Identity Discovery Collector ---
        elif col_name in ("Identity Discovery Collector", "Identity Discovery"):
            for prof in col.get("profiles", []):
                if prof.get("found"):
                    prov = prof.get("provider", "Unknown")
                    uname = prof.get("username")
                    dname = prof.get("display_name")
                    avatar = prof.get("avatar_url")
                    p_url = prof.get("profile_url")
                    loc = prof.get("location")
                    site = prof.get("website")
                    bio = prof.get("bio")
                    exec_time = prof.get("metadata", {}).get("execution_time_ms")

                    # Deduplicate with Account Presence profiles
                    if not any(p["provider"] == prov for p in profiles_found):
                        profiles_found.append({
                            "provider": prov,
                            "status": "REGISTERED",
                            "username": uname,
                            "display_name": dname,
                            "avatar_url": avatar,
                            "profile_url": p_url,
                            "location": loc,
                            "website": site,
                            "bio": bio,
                            "execution_time_ms": exec_time,
                        })

                    if uname and (prov, uname.lower()) not in seen_usernames_set:
                        seen_usernames_set.add((prov, uname.lower()))
                        discovered_usernames.append(
                            DiscoveredUsername(provider=prov, username=uname).to_dict()
                        )
                        username_candidates.append(
                            UsernameCandidate(provider=prov, username=uname, confidence="High").to_dict()
                        )

                    if avatar:
                        evidence_items.append(EvidenceItem("Public Avatar", avatar, prov).to_dict())
                    if dname:
                        evidence_items.append(EvidenceItem("Public Display Name", dname, prov).to_dict())
                    if uname:
                        evidence_items.append(EvidenceItem("Public Username", f"@{uname}", prov).to_dict())
                    if loc:
                        evidence_items.append(EvidenceItem("Public Location", loc, prov).to_dict())
                    if site:
                        evidence_items.append(EvidenceItem("Public Website", site, prov).to_dict())
                    if p_url:
                        evidence_items.append(EvidenceItem("Public Profile URL", p_url, prov).to_dict())

                    if avatar:
                        avatars_found.append({
                            "provider": prov,
                            "avatar_url": avatar,
                            "display_name": dname,
                            "username": uname,
                            "location": loc,
                            "website": site,
                            "profile_url": p_url,
                        })

        # --- Public Avatar Collector ---
        elif col_name in ("Public Avatar Collector", "Public Avatar"):
            for prov_res in col.get("providers", []):
                if prov_res.get("found") and prov_res.get("avatar_url"):
                    prov = prov_res.get("provider", "Unknown")
                    avatar = prov_res.get("avatar_url")
                    dname = prov_res.get("display_name")
                    p_url = prov_res.get("profile_url")
                    uname = prov_res.get("username")

                    if avatar:
                        avatars_found.append({
                            "provider": prov,
                            "avatar_url": avatar,
                            "display_name": dname,
                            "username": uname,
                            "profile_url": p_url,
                        })
                        evidence_items.append(EvidenceItem("Public Avatar", avatar, prov).to_dict())
                    if uname and (prov, uname.lower()) not in seen_usernames_set:
                        seen_usernames_set.add((prov, uname.lower()))
                        discovered_usernames.append(
                            DiscoveredUsername(provider=prov, username=uname).to_dict()
                        )
                        username_candidates.append(
                            UsernameCandidate(provider=prov, username=uname, confidence="High").to_dict()
                        )

        # --- Gravatar Collector ---
        elif col_name == "Gravatar Collector":
            if col.get("gravatar_exists") and col.get("avatar_url"):
                prov = "Gravatar"
                avatar = col.get("avatar_url")
                dname = col.get("display_name")
                p_url = col.get("profile_url")
                uname = col.get("username")

                avatars_found.append({
                    "provider": prov,
                    "avatar_url": avatar,
                    "display_name": dname,
                    "username": uname,
                    "profile_url": p_url,
                })
                evidence_items.append(EvidenceItem("Public Avatar", avatar, prov).to_dict())
                if uname and (prov, uname.lower()) not in seen_usernames_set:
                    seen_usernames_set.add((prov, uname.lower()))
                    discovered_usernames.append(
                        DiscoveredUsername(provider=prov, username=uname).to_dict()
                    )
                    username_candidates.append(
                        UsernameCandidate(provider=prov, username=uname, confidence="High").to_dict()
                    )

        # --- Public Git Collector ---
        elif col_name == "Public Git Collector":
            if col.get("commit_count", 0) > 0 or col.get("public_profile"):
                prov = "GitHub (Git Commits)"
                author = col.get("author_name")
                p_url = col.get("public_profile")
                if author:
                    evidence_items.append(EvidenceItem("Public Git Author Name", author, prov).to_dict())
                if p_url:
                    evidence_items.append(EvidenceItem("Public Profile URL", p_url, prov).to_dict())

    # Deduplicate Evidence Items by (type, value, provider)
    unique_evidence: list[dict[str, str]] = []
    seen_evidence_set: set[tuple[str, str, str]] = set()
    for item in evidence_items:
        key = (item["type"], item["value"], item["provider"])
        if key not in seen_evidence_set:
            seen_evidence_set.add(key)
            unique_evidence.append(item)

    # 2. Merge duplicate avatars into Unified Public Avatar Cards
    # Gravatar and Libravatar often share identical avatar hashes or serve identical default images for the email.
    # Also group by avatar_url or provider group.
    merged_avatars: list[dict[str, Any]] = []

    # Map gravatar & libravatar together if both present or if URLs match
    grav_item = next((a for a in avatars_found if a["provider"] == "Gravatar"), None)
    libra_item = next((a for a in avatars_found if a["provider"] == "Libravatar"), None)

    processed_avatar_providers = set()

    if grav_item or libra_item:
        providers_list = []
        profile_urls_dict = {}
        d_name = None
        u_name = None
        loc = None
        site = None
        av_url = None

        if grav_item:
            providers_list.append("Gravatar")
            if grav_item.get("profile_url"):
                profile_urls_dict["Gravatar"] = grav_item["profile_url"]
            d_name = d_name or grav_item.get("display_name")
            u_name = u_name or grav_item.get("username")
            loc = loc or grav_item.get("location")
            site = site or grav_item.get("website")
            av_url = av_url or grav_item.get("avatar_url")
            processed_avatar_providers.add("Gravatar")

        if libra_item:
            providers_list.append("Libravatar")
            if libra_item.get("profile_url"):
                profile_urls_dict["Libravatar"] = libra_item["profile_url"]
            d_name = d_name or libra_item.get("display_name")
            u_name = u_name or libra_item.get("username")
            loc = loc or libra_item.get("location")
            site = site or libra_item.get("website")
            av_url = av_url or libra_item.get("avatar_url")
            processed_avatar_providers.add("Libravatar")

        if av_url:
            merged_avatars.append(
                UnifiedAvatarCard(
                    avatar_url=av_url,
                    display_name=d_name,
                    primary_username=u_name,
                    location=loc,
                    website=site,
                    providers=providers_list,
                    profile_urls=profile_urls_dict,
                ).to_dict()
            )

    # Process remaining distinct provider avatars (e.g. GitHub, GitLab)
    for a in avatars_found:
        prov = a["provider"]
        if prov not in processed_avatar_providers:
            processed_avatar_providers.add(prov)
            p_dict = {}
            if a.get("profile_url"):
                p_dict[prov] = a["profile_url"]
            merged_avatars.append(
                UnifiedAvatarCard(
                    avatar_url=a["avatar_url"],
                    display_name=a.get("display_name"),
                    primary_username=a.get("username"),
                    location=a.get("location"),
                    website=a.get("website"),
                    providers=[prov],
                    profile_urls=p_dict,
                ).to_dict()
            )

    # 3. Select Primary Identity Profile
    primary_identity = None
    if profiles_found:
        # Priority: GitHub -> GitLab -> Gravatar -> Libravatar -> Docker Hub -> Reddit
        priority_map = {"GitHub": 1, "GitLab": 2, "Gravatar": 3, "Libravatar": 4, "Docker Hub": 5, "Reddit": 6}
        sorted_profiles = sorted(profiles_found, key=lambda p: priority_map.get(p["provider"], 99))
        primary_identity = sorted_profiles[0]

    # 4. Confidence Scoring and Rationale
    reasons: list[str] = []
    if merged_avatars:
        reasons.append("Public avatar found")
    if profiles_found:
        reasons.append("Public profile found")
    if discovered_usernames:
        reasons.append("Public username extracted")
    if len(profiles_found) >= 2 or len(merged_avatars) >= 2 or len(processed_avatar_providers) >= 2:
        reasons.append("Multiple providers agree")

    # Check mailbox verification status from verification collector
    ver_col = next((c for c in collector_results if c.get("collector") == "Verification Collector"), None)
    if ver_col and ver_col.get("mailbox_status") in ("Verified", "Likely Exists"):
        reasons.append("Mailbox verified active")

    dom_col = next((c for c in collector_results if c.get("collector") == "Domain Collector"), None)
    if dom_col and dom_col.get("has_mx") and (dom_col.get("spf") or dom_col.get("dmarc")):
        reasons.append("Valid domain & mail servers")

    if len(reasons) >= 3 or "Multiple providers agree" in reasons:
        confidence = "HIGH"
    elif len(reasons) >= 1:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    identity_summary = IdentitySummary(
        profiles_found=len(profiles_found),
        primary_identity=primary_identity,
        evidence_count=len(unique_evidence),
        confidence=confidence,
        reasons=reasons,
    ).to_dict()

    # 5. Build Identity Discovery Timeline
    timeline: list[dict[str, str]] = [
        TimelineStep(
            step="1",
            label="Email Parsed",
            description=f"Target email address '{target_email}' successfully parsed and syntax validated."
        ).to_dict()
    ]

    step_counter = 2

    for p in profiles_found:
        prov = p["provider"]
        timeline.append(
            TimelineStep(
                step=str(step_counter),
                label=f"{prov} Profile Found",
                description=f"Public profile confirmed on {prov}."
            ).to_dict()
        )
        step_counter += 1

    if discovered_usernames:
        timeline.append(
            TimelineStep(
                step=str(step_counter),
                label="Username Extracted",
                description=f"Extracted {len(discovered_usernames)} real public handle(s) across providers."
            ).to_dict()
        )
        step_counter += 1

    if merged_avatars:
        timeline.append(
            TimelineStep(
                step=str(step_counter),
                label="Avatar Retrieved",
                description=f"Retrieved {len(merged_avatars)} unified avatar preview(s)."
            ).to_dict()
        )
        step_counter += 1

    timeline.append(
        TimelineStep(
            step=str(step_counter),
            label="Evidence Generated",
            description=f"Compiled {len(unique_evidence)} verified evidence item(s) for identity correlation."
        ).to_dict()
    )

    return {
        "identity_summary": identity_summary,
        "evidence": unique_evidence,
        "public_avatar": merged_avatars,
        "discovered_usernames": discovered_usernames,
        "username_candidates": username_candidates,
        "timeline": timeline,
        "future_providers": PLANNED_PROVIDERS,
        "profiles": profiles_found,
    }
