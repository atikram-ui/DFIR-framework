import sys, os

# Add modules directory directly to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules"))

from ti_enrichment import enrich_all_iocs, print_ti_summary, ensure_ti_table

args = sys.argv[1:]
print("=" * 55)
print("   DFIR Framework - Phase 9: Threat Intelligence")
print("=" * 55)

if "--summary-only" in args:
    ensure_ti_table()
    print_ti_summary()
else:
    enrich_all_iocs(mock_mode=True)
