"""Convert SWE-chat (SALT-NLP/SWE-chat, ODC-By) tool calls into agbench call records.

Usage: python bench/tools/swechat_calls.py OUT.jsonl [LOCAL_PARQUET]

Needs `pip install duckdb` and a Hugging Face token that has accepted the
dataset's terms. Reads only the needed columns of conversations.parquet and
sessions.parquet at a pinned revision (or a local extract made earlier) and
writes one record per shell or file-tool call, with developer = user_id.
"""

import json
import os
import sys

import duckdb

sys.path.insert(0, os.path.dirname(__file__))
from dataclaw_calls import shell_params  # noqa: E402

REV = "202b071f18e03c79df5a7287565ce2ebc5ee7756"
SHELL = {"Bash": "Bash", "bash": "Bash", "exec_command": "exec_command", "Execute": "exec_command"}
FILE_TOOLS = {"Read", "Edit", "Write", "NotebookEdit", "Grep"}


def main(out, local=None):
    con = duckdb.connect()
    if local:
        src = f"'{local}'"
    else:
        con.execute("INSTALL httpfs; LOAD httpfs;")
        con.execute("CREATE SECRET hf (TYPE huggingface, PROVIDER credential_chain)")
        base = f"hf://datasets/SALT-NLP/SWE-chat@{REV}"
        src = f"""(SELECT c.session_id, c.turn_number, c.tool_name, c.command, c.file_path, s.user_id, s.agent AS s_agent
                  FROM '{base}/conversations.parquet' c JOIN '{base}/sessions.parquet' s USING (session_id)
                  WHERE c.turn_type = 'tool_use')"""
    rows = con.execute(f"""SELECT user_id, session_id, s_agent, tool_name, command, file_path
                           FROM {src} WHERE user_id IS NOT NULL ORDER BY session_id, turn_number""")
    n = 0
    with open(out, "w", encoding="utf-8") as w:
        while True:
            batch = rows.fetchmany(50000)
            if not batch:
                break
            for user, sid, agent, tool, cmd, fpath in batch:
                if tool in SHELL and isinstance(cmd, str):
                    r = shell_params(SHELL[tool], {"command": cmd})
                    if not r:
                        continue
                    t, params = r
                elif tool in FILE_TOOLS and isinstance(fpath, str):
                    t, params = tool, {"file_path": fpath}
                else:
                    continue
                w.write(json.dumps({"dev": "swe:" + user, "session": sid, "agent": agent, "tool": t,
                                    "params": params, "complete": True}) + "\n")
                n += 1
    print(json.dumps({"calls": n}))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
