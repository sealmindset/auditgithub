#!/usr/bin/env python3
"""
Test script for Zero Day Analysis enhancements.
Tests fuzzy matching, multi-source search, and scope filtering.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.ai_agent.tools.db_tools import (
    normalize_package_name,
    search_dependencies,
    search_findings,
    search_languages,
    search_all_sources
)

# Connect to DB
url = 'postgresql://postgres:postgres@localhost:5432/auditgh_kb'
engine = create_engine(url)
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

print("="*60)
print("ZERO DAY ANALYSIS - ENHANCEMENT TESTS")
print("="*60)

# Test 1: Fuzzy Package Name Normalization
print("\n[TEST 1] Fuzzy Package Name Normalization")
print("-" * 60)
test_names = ["React.JS", "Next.JS", "react", "next.js", "log4j"]
for name in test_names:
    variants = normalize_package_name(name)
    print(f"  {name:15} → {variants}")

# Test 2: Fuzzy Dependency Search
print("\n[TEST 2] Fuzzy Dependency Search")
print("-" * 60)
for query in ["React.JS", "Next", "next.js"]:
    results = search_dependencies(session, query, use_fuzzy=True)
    print(f"  Query '{query}': Found {len(results)} repos")
    for r in results:
        print(f"    - {r['repository']}: {r['package_name']} v{r['version']}")

# Test 3: Multi-Source Search
print("\n[TEST 3] Multi-Source Search (All Sources)")
print("-" * 60)
all_results = search_all_sources(session, "react")
print(f"  Query 'react':")
for source, items in all_results.items():
    if source != "aggregated_repositories":
        print(f"    {source}: {len(items)} results")

print(f"  Unique repos: {len(all_results.get('aggregated_repositories', []))}")

# Test 4: Scoped Search (Dependencies only)
print("\n[TEST 4] Scoped Search (Dependencies Only)")
print("-" * 60)
scoped_results = search_all_sources(session, "react", scopes=["dependencies"])
for source, items in scoped_results.items():
    if source != "aggregated_repositories":
        print(f"    {source}: {len(items)} results")

# Test 5: Language Search
print("\n[TEST 5] Language Search")
print("-" * 60)
lang_results = search_languages(session, "TypeScript", use_fuzzy=True)
print(f"  Query 'TypeScript': Found {len(lang_results)} repos")
for r in lang_results[:5]:
    print(f"    - {r['repository']} ({r.get('language')})")

print("\n" + "="*60)
print("TESTS COMPLETE")
print("="*60)

session.close()
