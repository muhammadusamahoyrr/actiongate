"""Off-the-shelf parser front end for the exploratory "tree-sitter" ablation.

The shipped analyzer derives facts from an mvdan.cc/sh syntax tree. This
script replaces that parser with tree-sitter-bash (an independent, widely used
grammar) and hands the frozen per-command semantics a command that needs no
parsing: one simple command per line, every word quoted, static variables
substituted, here-document bodies kept under a quoted delimiter when static.
agbench reads the output with a pack spec NAME=front:MAP:with:tokplus:PACK,
so the analyzer and packs (hash 6809d27d) are unchanged; the frozen
tokenizer+ path only splits the already structured lines.

Mapping from the syntax tree, kept close to the shipped analyzer:
  * lists, pipelines, subshells, groups, if/while/for/case bodies and function
    bodies: every simple command inside is emitted; pipes stay on one line so
    the right-hand side still reads a pipe;
  * prefix assignments (FOO=1 cmd) are dropped; standalone static assignments
    are recorded and substituted; non-static ones forget the variable;
  * command and process substitutions: the inner commands are emitted, the
    word becomes non-static;
  * here-documents: static body -> quoted delimiter (inspected as code);
    body with expansions -> the command reads a pipe (opaque to interpreters);
    here-strings with a static word become a static here-document;
  * input redirection from a file: emitted as `cat FILE`, so a credential file
    redirected into any command is a secret read, as in the shipped analyzer;
  * literal code given to sh/bash/zsh -c is front-ended recursively;
  * a newline inside a word becomes "; " (the line-based splitter cannot
    carry it); a tree with an ERROR or MISSING node fails closed as a computed
    command name, mirroring "command does not parse as shell".

Usage:
  python bench/tools/ts_front.py OUT.jsonl INPUT [INPUT ...]
INPUT is a benchmark or call file (JSON lines with tool and params.command) or
a directory of Claude Code transcripts (*.jsonl, searched recursively). OUT
holds {"h": sha256(command), "out": front-ended command} per distinct Bash
command. Only commands are read; nothing is printed but counts.
"""

import hashlib
import json
import os
import sys

import tree_sitter as ts
import tree_sitter_bash as tsb

PARSER = ts.Parser(ts.Language(tsb.language()))
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun"}
DELIM = "__TSEOF__"
FAIL = '"$__ts_parse_error"'
COMPOUND = {"subshell", "compound_statement", "if_statement", "elif_clause", "else_clause", "while_statement",
            "for_statement", "c_style_for_statement", "case_statement", "case_item", "do_group",
            "function_definition", "list", "program", "negated_command", "test_command"}


class Fail(Exception):
    pass


def text(n):
    return n.text.decode("utf-8", "replace")


def q_lit(s):
    return "'" + s.replace("'", "'\\''") + "'"


def q_dyn(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unescape_word(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            if s[i + 1] != "\n":
                out.append(s[i + 1])
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def unescape_dq(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in '"\\$`\n':
            if s[i + 1] != "\n":
                out.append(s[i + 1])
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


ANSI = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b", "e": "\x1b",
        "f": "\f", "v": "\v"}


def ansi_c(s):
    body = s[2:-1]
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            d = body[i + 1]
            if d in ANSI:
                out.append(ANSI[d])
                i += 2
                continue
            if d == "x":
                j = i + 2
                while j < len(body) and j < i + 4 and body[j] in "0123456789abcdefABCDEF":
                    j += 1
                if j > i + 2:
                    out.append(chr(int(body[i + 2:j], 16)))
                    i = j
                    continue
            if d in "01234567":
                j = i + 1
                while j < len(body) and j < i + 4 and body[j] in "01234567":
                    j += 1
                out.append(chr(int(body[i + 1:j], 8)))
                i = j
                continue
            out.append(d)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


class Front:
    def __init__(self):
        self.vars = {}
        self.lines = []
        self.reads_pipe = False

    def cmdline(self, n):
        """Front-ends one simple command; returns its line and whether it reads a pipe."""
        self.reads_pipe = False
        line = self.emit_args(self.simple(n))
        return line, self.reads_pipe

    # ---- words -------------------------------------------------------------
    def word(self, n):
        """Returns (text, static) for one argument node."""
        t = n.type
        if t in ("word", "number"):
            return unescape_word(text(n)), True
        if t == "raw_string":
            return text(n)[1:-1], True
        if t == "ansi_c_string":
            return ansi_c(text(n)), True
        if t == "translated_string":
            return self.word(n.named_children[0]) if n.named_children else ("", True)
        if t == "string":
            parts, static = [], True
            for c in n.named_children:
                if c.type == "string_content":
                    parts.append(unescape_dq(text(c)))
                else:
                    s, ok = self.word(c)
                    parts.append(s)
                    static = static and ok
            if not n.named_children:
                inner = text(n)[1:-1]
                parts.append(unescape_dq(inner))
            return "".join(parts), static
        if t == "concatenation":
            parts, static = [], True
            for c in n.children:
                s, ok = self.word(c)
                parts.append(s)
                static = static and ok
            return "".join(parts), static
        if t == "simple_expansion":
            name = text(n)[1:]
            if name in self.vars:
                return self.vars[name], True
            return text(n), False
        if t == "expansion":
            kids = n.named_children
            if len(kids) == 1 and kids[0].type == "variable_name" and text(n) == "${" + text(kids[0]) + "}":
                name = text(kids[0])
                if name in self.vars:
                    return self.vars[name], True
            return text(n), False
        if t in ("command_substitution", "process_substitution"):
            for c in n.named_children:
                self.stmt(c, False)
            return "$(_)", False
        if t in ("arithmetic_expansion", "brace_expression"):
            return text(n), t == "brace_expression"
        if t == "special_variable_name" or t == "variable_name":
            return text(n), False
        if not n.is_named:  # punctuation inside a concatenation, e.g. '=' or ':'
            return text(n), True
        return text(n), False

    def emit_args(self, args):
        out = []
        for s, ok in args:
            s = s.replace("\r\n", "\n").replace("\n", "; ")
            out.append(q_lit(s) if ok else q_dyn(s))
        return " ".join(out)

    # ---- statements --------------------------------------------------------
    def simple(self, n, piped_from=None, heredoc=None, extra_in=None):
        """Emits one simple command; returns its line text (without heredoc)."""
        args, proc = [], []
        for c in n.children:
            if c.type == "variable_assignment":
                continue  # prefix assignment: the shipped analyzer ignores it too
            if c.type == "command_name":
                args.append(self.word(c.named_children[0]) if c.named_children else (text(c), True))
                proc.append(False)
            elif c.is_named and c.type not in ("comment", "file_redirect", "herestring_redirect"):
                args.append(self.word(c))
                proc.append(c.type == "process_substitution")
        # A shell or interpreter whose script operand is a process substitution
        # runs whatever that command prints; the line format has no word for
        # this, so it becomes a command reading its program from a pipe.
        if args and args[0][1] and os.path.basename(args[0][0]) in SHELLS | INTERPRETERS:
            for i in range(1, len(args)):
                if not args[i][0].startswith("-") or proc[i]:
                    if proc[i]:
                        self.reads_pipe = True
                        args = args[:i] + args[i + 1:]
                    break
        args = self.nested(args)
        return args

    def nested(self, args):
        if len(args) >= 3 and args[0][1] and os.path.basename(args[0][0]) in SHELLS:
            for i, (s, ok) in enumerate(args[1:], 1):
                if s == "-c" and i + 1 < len(args) and args[i + 1][1]:
                    sub = front(args[i + 1][0])
                    if DELIM not in sub:
                        args = args[:i + 1] + [(sub.replace("\n", "; "), True)] + args[i + 2:]
                    break
        return args

    def redirects(self, nodes):
        """Returns (heredoc_body, heredoc_static, rest_pipeline_node, input_files)."""
        body, static, rest, files = None, True, None, []
        for r in nodes:
            if r.type == "heredoc_redirect":
                parts = []
                for c in r.named_children:
                    if c.type == "heredoc_body":
                        parts.append(text(c))
                        static = static and not any(k.type in ("simple_expansion", "expansion", "command_substitution",
                                                               "arithmetic_expansion") for k in c.named_children)
                        for k in c.named_children:
                            if k.type == "command_substitution":
                                self.word(k)
                    elif c.type in ("pipeline", "command", "list", "redirected_statement"):
                        rest = c
                if body is None:
                    body = "".join(parts)
                    if body.endswith("\n"):
                        body = body[:-1]
                    # strip the delimiter line tree-sitter keeps at the end of the body
            elif r.type == "herestring_redirect":
                w = r.named_children[0] if r.named_children else None
                if w is not None and body is None:
                    s, ok = self.word(w)
                    body, static = s, ok
            elif r.type == "file_redirect":
                op = text(r).lstrip("0123456789")
                dest = r.child_by_field_name("destination")
                if dest is None and r.named_children:
                    dest = r.named_children[-1]
                if dest is not None and op.startswith("<") and not op.startswith("<&") and not op.startswith("<<"):
                    s, _ = self.word(dest)
                    files.append(s)
                elif dest is not None:
                    self.word(dest)  # visit substitutions in output targets
        return body, static, rest, files

    def stmt(self, n, piped):
        t = n.type
        if t == "comment":
            return
        if t == "command":
            line, rp = self.cmdline(n)
            piped = piped or rp
            redirs = [c for c in n.children if c.type in ("file_redirect", "herestring_redirect")]
            body, static, _, files = self.redirects(redirs)
            for f in files:
                self.lines.append("cat " + q_lit(f))
            if line:
                if body is not None:
                    self.heredoc(line, body, static, piped)
                else:
                    self.lines.append(("true | " if piped else "") + line)
            return
        if t == "redirected_statement":
            inner = n.child_by_field_name("body")
            redirs = [c for c in n.children if c is not inner]
            body, static, rest, files = self.redirects(redirs)
            for f in files:
                self.lines.append("cat " + q_lit(f))
            if inner is None:
                return
            if inner.type == "command" and body is not None:
                line, rp = self.cmdline(inner)
                piped = piped or rp
                inner_redirs = [c for c in inner.children if c.type in ("file_redirect", "herestring_redirect")]
                _, _, _, files2 = self.redirects(inner_redirs)
                for f in files2:
                    self.lines.append("cat " + q_lit(f))
                tail = self.pipe_tail(rest) if rest is not None else ""
                self.heredoc(line + tail, body, static, piped)
                if rest is not None and tail == "":
                    self.stmt(rest, True)
                return
            self.stmt(inner, piped)
            if rest is not None:
                self.stmt(rest, True)
            return
        if t == "pipeline":
            kids = [c for c in n.named_children if c.type != "comment"]
            if all(k.type == "command" and not self.has_heredoc(k) for k in kids):
                lines = []
                for k in kids:
                    for f in self.redirects([c for c in k.children if c.type == "file_redirect"])[3]:
                        self.lines.append("cat " + q_lit(f))
                    line, rp = self.cmdline(k)
                    lines.append(("true | " if rp else "") + line if line else "")
                self.lines.append(("true | " if piped else "") + " | ".join(l for l in lines if l))
                return
            for i, k in enumerate(kids):
                self.stmt(k, piped or i > 0)
            return
        if t == "variable_assignment":
            name_node = n.child_by_field_name("name")
            val = n.child_by_field_name("value")
            name = text(name_node) if name_node is not None else ""
            if val is None:
                s, ok = "", True
            else:
                s, ok = self.word(val)
            if ok and name.isidentifier() and "\n" not in s:
                self.vars[name] = s
                self.lines.append(name + "=" + q_lit(s))
            else:
                self.vars.pop(name, None)
            return
        if t == "variable_assignments":
            for c in n.named_children:
                self.stmt(c, piped)
            return
        if t == "declaration_command":
            for c in n.named_children:
                if c.type == "variable_assignment":
                    self.stmt(c, piped)
            return
        if t in ("for_statement", "select_statement"):
            for c in n.named_children:
                if c.type == "variable_name":
                    self.vars.pop(text(c), None)
                elif c.type not in ("do_group",):
                    self.word(c)
            for c in n.named_children:
                if c.type == "do_group":
                    self.stmt(c, False)
            return
        if t in COMPOUND or t in ("unset_command",):
            for c in n.named_children:
                if c.type in ("word", "string", "raw_string", "concatenation", "simple_expansion", "expansion",
                              "command_substitution", "test_operator", "binary_expression", "unary_expression",
                              "parenthesized_expression", "number", "extglob_pattern", "regex", "case_item"):
                    if c.type == "case_item":
                        self.stmt(c, False)
                    else:
                        self.visit_subst(c)
                    continue
                self.stmt(c, piped and t == "list" and False)
            return
        # anything else (test expressions, arithmetic): visit substitutions only
        self.visit_subst(n)

    def visit_subst(self, n):
        if n.type in ("command_substitution", "process_substitution"):
            for c in n.named_children:
                self.stmt(c, False)
            return
        for c in n.named_children:
            self.visit_subst(c)

    def has_heredoc(self, n):
        return any(c.type in ("heredoc_redirect", "herestring_redirect") for c in n.children)

    def pipe_tail(self, rest):
        if rest.type == "command" and not self.has_heredoc(rest):
            return " | " + self.cmdline(rest)[0]
        if rest.type == "pipeline" and all(k.type == "command" for k in rest.named_children):
            return "".join(" | " + self.cmdline(k)[0] for k in rest.named_children)
        return ""

    def heredoc(self, line, body, static, piped):
        if static and DELIM not in body:
            self.lines.append(line + " <<'" + DELIM + "'")
            self.lines.extend(body.split("\n"))
            self.lines.append(DELIM)
        else:
            # body built at run time: the command reads input the analyzer cannot see
            self.lines.append("true | " + line)


def front(cmd):
    tree = PARSER.parse(cmd.encode("utf-8", "replace"))
    if tree.root_node.has_error:
        return FAIL
    f = Front()
    try:
        f.stmt(tree.root_node, False)
    except (Fail, RecursionError):
        return FAIL
    return "\n".join(f.lines)


def commands(path):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for name in files:
                if name.endswith(".jsonl"):
                    yield from transcript(os.path.join(root, name))
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("tool") in ("Bash", "bash"):
                c = (r.get("params") or {}).get("command")
                if isinstance(c, str):
                    yield c


def transcript(path):
    if os.name == "nt":
        path = "\\\\?\\" + os.path.abspath(path)  # transcript paths can exceed MAX_PATH
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            msg = r.get("message") if isinstance(r, dict) else None
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                continue
            for c in content:
                if isinstance(c, dict) and c.get("type") == "tool_use" and c.get("name") == "Bash":
                    cmd = (c.get("input") or {}).get("command")
                    if isinstance(cmd, str):
                        yield cmd


def main():
    out, inputs = sys.argv[1], sys.argv[2:]
    sys.setrecursionlimit(10000)
    seen, failed = set(), 0
    with open(out, "w", encoding="utf-8") as w:
        for p in inputs:
            for cmd in commands(p):
                h = hashlib.sha256(cmd.encode("utf-8")).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                o = front(cmd)
                failed += o == FAIL
                w.write(json.dumps({"h": h, "out": o}) + "\n")
    print(f"{len(seen)} distinct Bash commands, {failed} failed to parse (fail closed)")


if __name__ == "__main__":
    main()
