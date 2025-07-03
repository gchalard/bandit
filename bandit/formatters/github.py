#
# SPDX-License-Identifier: Apache-2.0
r"""
==============
GitHub formatter
==============

This formatter outputs the issues in GitHub API endpoint for issues JSON format.

:Example:

.. code-block:: javascript
[
  {
    "title": "issue_text found in filename",
    "body": "issue_text \nFile: filename \nCWE: \n\tid: issue_cwe.id \n\tlink: issue_cwe.link \nSeverity: issue_severity \nConfidence: issue_confidence \ncode: \n\`\`\`python \ncode \n\`\`\` \nReference: more_info",
    "labels": [
      issue_severity,
      "sast",
      "bandit",
      "security"
    ]
  },
  ...
]

"""

import datetime
import json
import logging
import operator
import sys
from typing import Dict, List

from bandit.core import docs_utils
from bandit.core import test_properties

LOG = logging.getLogger(__name__)


@test_properties.accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """''Prints issues in JSON format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    machine_output = {"results": [], "errors": []}

    output: List[Dict[str, str]] = list()

    results = manager.get_issue_list(
        sev_level=sev_level, conf_level=conf_level
    )

    baseline = not isinstance(results, list)

    if baseline:
        collector = []
        for result in results:
            result_dict = result.as_dict(max_lines=lines)
            result_dict["more_info"] = docs_utils.get_url(result_dict["test_id"])
            if len(results[result]) > 1:
                result_dict["candidates"] = [
                    candidate.as_dict(max_lines=lines) for candidate in results[result]
                ]
            collector.append(result_dict)

    else:
        collector = [result.as_dict(max_lines=lines) for result in results]
        for elem in collector:
            elem["more_info"] = docs_utils.get_url(elem["test_id"])

    itemgetter = operator.itemgetter
    if manager.agg_type == "vuln":
        machine_output["results"] = sorted(
            collector, key=itemgetter("test_name")
        )
    else:
        machine_output["results"] = sorted(
            collector, key=itemgetter("filename")
        )

    LOG.debug(json.dumps(machine_output, indent=4))

    for result in machine_output["results"]:
        result_dict = {
            "title": f"{result['issue_text']} found in {result['filename']}",
            "body": (
                f"{result['issue_text']}\n"
                f"File: {result['filename']}\n"
                "CWE: \n"
                f"\tid: {result['issue_cwe']['id']}\n"
                f"\tlink: {result['issue_cwe']['link']}\n"
                f"Severity: {result['issue_severity']}\n"
                f"Confidence: {result['issue_confidence']}\n"
                "Code:\n"
                "```python3\n"
                f"{result['code']}\n"
                "```\n"
                f"Reference: {result['more_info']}"
            ),
            "labels": [
                "sast",
                "bandit",
                "security",
                result["issue_severity"]
            ]
        }

        output.append(result_dict)
        

    result = json.dumps(
        output, sort_keys=True, indent=2, separators=(",", ": ")
    )

    with fileobj:
        fileobj.write(result)

    if fileobj.name != sys.stdout.name:
        LOG.info("JSON output written to file: %s", fileobj.name)
