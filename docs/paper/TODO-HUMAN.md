# Left for a human

These items cannot be done offline, or they need human judgment or the authors' approval. Nothing here has been faked or filled in.

## Decisions for the authors
- [ ] **Choose the title** from TITLE-OPTIONS.md, or keep the current one.
- [ ] **Push** branch `research/action-bench` and tag `pre-round5`. Both are local only; nothing has been pushed.

## Human judgment
- [ ] **Human labels.** Two people (the first author and Awais Khalid) label `bench/human/label-kit.html` independently, following `bench/human/LABELING-GUIDE.md`, and export their JSON files. Then run:
  ```bash
  python bench/tools/agreement.py bench/human/label-kit-key.jsonl bench/human/audit-key.jsonl \
    labels-A.json labels-B.json --agent bench/human/labels-claude-agent.json
  ```
  Report the human–human kappa, the human–agent kappa and the H3 result in the paper.
- [ ] **Verify the recent references.** Go through REFS-TO-VERIFY.md by hand.
- [ ] **Confirm Awais Khalid's contribution statement** in the acknowledgment.
- [ ] **Confirm who "reviewers of earlier drafts"** in the acknowledgment refers to.

## External services
- [ ] Deposit the pre-specification and the analyzer hash on OSF or Zenodo for an external timestamp. Until then the paper says "pre-specified", not "pre-registered".
- [ ] Rotate or delete the Hugging Face token that was pasted into a chat (account usama1111).
- [ ] Find an arXiv endorser, if needed, and check the target venue's page limit. The paper is now 12 pages.
