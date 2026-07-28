from backend.analyzer.response.playbook_loader import PlaybookLoader

loader = PlaybookLoader()

print(loader.get_playbook("BRUTE_FORCE"))