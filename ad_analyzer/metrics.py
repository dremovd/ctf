import itertools
import requests
from metrics_samples import source_labeled

url = "http://localhost:8000/analyze"

for file_path, vulnarabilities_correct in source_labeled:
    with open(file_path, "r") as f:
        files = {"file": (file_path, f)}
        response = requests.post(url, files=files)

    # Only compare analyzer line numbers and correct 
    correct_vulnarabilities = set(itertools.chain.from_iterable([
        v.line_numbers
        for v in vulnarabilities_correct
    ]))
    response_vulnarabilities = set(itertools.chain.from_iterable([
        v['line_numbers']
        for v in response.json()
    ]))

    all_vulnerabilities = correct_vulnarabilities.union(response_vulnarabilities)
    jaccard_smooth = (
        (1 + len(correct_vulnarabilities.intersection(response_vulnarabilities)))
        / (1 + len(all_vulnerabilities))
    )

    print(f'Jaccard metric: {jaccard_smooth:.2f}')
    print(response.status_code)
    print(response.json())
