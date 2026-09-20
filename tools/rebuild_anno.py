#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Rebuild annotated source files on top of latest master.
#
#   output = master code (unchanged, incl. master's own comments)
#          + user annotation comments re-inserted (matched via code context)
#   comments whose code was deleted/changed in master are dropped.
#
# Method (old-based isolation):
#   anno  = annotated branch file (b4a5c8d79)          [has comments + possible damage]
#   old   = pure baseline file (d44205284 = nginx 1.31.1) [clean]
#   new   = latest master file  (origin/master = 1.31.7)   [clean target]
#
#   1. Blank comments -> code skeletons.
#   2. Align anno->old (equal code lines) and old->new.
#   3. For each anno code line mapped into new:
#        - leading annotation block = anno's preceding comment lines
#          MINUS old's own comment lines (isolates user annotations)
#        - trailing annotation = anno trailing comment MINUS old's trailing
#   4. Emit new lines, inserting annotations before mapped code lines.
import subprocess, difflib, os, sys, io, bisect

ANNO  = 'b4a5c8d79'
OLD   = 'd44205284'
MASTER = 'origin/master'
REPO  = '/workspace/nginx-anno'

def git_show(rev, path):
    try:
        data = subprocess.check_output(['git', 'show', '%s:%s' % (rev, path)])
    except subprocess.CalledProcessError:
        return None
    if isinstance(data, bytes):
        data = data.decode('utf-8', 'replace')
    return data

def blank_c(text):
    out = []; i = 0; n = len(text); state = 'code'
    while i < n:
        c = text[i]
        if state == 'code':
            if c == '/' and i+1 < n and text[i+1] == '*':
                out += [' ', ' ']; state = 'block'; i += 2; continue
            if c == '/' and i+1 < n and text[i+1] == '/':
                out.append(' '); i += 1; state = 'line'; continue
            if c == '"': state = 'str'; out.append(c); i += 1; continue
            if c == "'": state = 'char'; out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        if state == 'block':
            if c == '*' and i+1 < n and text[i+1] == '/':
                out += [' ', ' ']; state = 'code'; i += 2; continue
            if c == '\n': out.append(c); i += 1; continue
            out.append(' '); i += 1; continue
        if state == 'line':
            if c == '\n': out.append(c); state = 'code'; i += 1; continue
            out.append(' '); i += 1; continue
        if state == 'str':
            if c == '\\': out.append(c); out.append(text[i+1]); i += 2; continue
            if c == '"': out.append(c); state = 'code'; i += 1; continue
            out.append(c); i += 1; continue
        if state == 'char':
            if c == '\\': out.append(c); out.append(text[i+1]); i += 2; continue
            if c == "'": out.append(c); state = 'code'; i += 1; continue
            out.append(c); i += 1; continue
    return ''.join(out)

def blank_sh(text):
    out = []; i = 0; n = len(text); dq = sq = False
    while i < n:
        c = text[i]
        if sq:
            if c == "'": sq = False
            out.append(c); i += 1; continue
        if dq:
            if c == '\\' and i+1 < n and text[i+1] in '"\\$`':
                out.append(c); out.append(text[i+1]); i += 2; continue
            if c == '"': dq = False
            out.append(c); i += 1; continue
        if c == "'": sq = True; out.append(c); i += 1; continue
        if c == '"': dq = True; out.append(c); i += 1; continue
        if c == '#':
            prev = text[i-1] if i > 0 else ''
            if i == 0 or prev.isspace() or prev in ';&|()<>':
                while i < n and text[i] != '\n':
                    out.append(' '); i += 1
                continue
            out.append(c); i += 1; continue
        out.append(c); i += 1; continue
    return ''.join(out)

def blank(path, text):
    if path.startswith('auto/'):
        return blank_sh(text)
    return blank_c(text)

def is_comment(path, line):
    return blank(path, line) != line

def normalize_comment_block(lines):
    # Keep only structurally valid, self-contained comment units, preserving
    # their original order. A leading gap may be a MIX of "//"-line comments
    # and "/* ... */" block comments (e.g. a "//" note above a "/* */" block);
    # each such unit is validated independently rather than rejecting the whole
    # sequence, so mixed annotations survive.
    #
    #   - a single "//" (or shell "#") line comment   -> kept
    #   - a block that opens with "/*" and closes with "*/" -> kept (its
    #     " * ..." continuation lines belong to the block)
    # Anything else (bare " * ..." continuation lines, orphan "*/" closers,
    # a block whose opener has no closer) is dropped so the emitted source
    # always stays valid C.
    lines = [l for l in lines if l.strip() != '']
    out = []
    i = 0
    n = len(lines)
    while i < n:
        l = lines[i]
        s = l.lstrip()
        if s.startswith(('#', '//')):
            out.append(l); i += 1; continue
        if s.startswith('/*'):
            j = i
            while j < n and not lines[j].strip().endswith('*/'):
                j += 1
            if j < n:
                out.extend(lines[i:j + 1])   # complete block opener..closer
                i = j + 1
            else:
                i += 1                        # opener with no closer -> drop
            continue
        i += 1                                # dangling " * ..." tail -> drop
    return out

def comment_gap_start(line, i):
    # Index of the first whitespace char of the gap between code and the
    # trailing comment marker at index i, so the emitted line keeps the
    # spaces/tabs that separated code from "//". If the marker is directly
    # against code (e.g. "fd;// x"), returns i (no gap).
    j = i
    while j > 0 and line[j-1] in ' \t':
        j -= 1
    return j

def trailing_comment(line):
    # Return the trailing comment substring that covers the rest of the line,
    # INCLUDING the whitespace gap that separates it from the code (e.g.
    # "      // 注释" or "  /* x */" at line end), or None. A mid-line comment
    # like the " /* void */" in "for (i = 0; /* void */; i++)" is NOT trailing
    # and is skipped.
    i = 0; n = len(line)
    while i < n:
        c = line[i]
        if c == '/' and i+1 < n and line[i+1] == '/':
            if line[:i].strip() != '':
                return line[comment_gap_start(line, i):]
            return None
        if c == '/' and i+1 < n and line[i+1] == '*':
            j = line.find('*/', i + 2)
            if j == -1:
                if line[:i].strip() != '':
                    return line[comment_gap_start(line, i):]
                return None
            if line[j+2:].strip() == '':
                if line[:i].strip() != '':
                    return line[comment_gap_start(line, i):j+2]
                return None
            i = j + 2          # mid-line comment; continue past it
            continue
        if c == '"':
            i += 1
            while i < n:
                if line[i] == '\\': i += 2; continue
                if line[i] == '"': i += 1; break
                i += 1
            continue
        if c == "'":
            i += 1
            while i < n:
                if line[i] == '\\': i += 2; continue
                if line[i] == "'": i += 1; break
                i += 1
            continue
        i += 1
    return None

def code_indices(skel):
    return [i for i, l in enumerate(skel) if l.strip() != '']

def leading_gap(skel):
    # for each code index, the list of preceding non-code (comment/blank) indices
    gap = {}
    pending = []
    for i, l in enumerate(skel):
        if l.strip() != '':
            gap[i] = pending[:]
            pending = []
        else:
            pending.append(i)
    return gap

def align(a, b):
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    m = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for d in range(i2 - i1):
                m[i1 + d] = j1 + d
    return m

def block_start(j, master_lines):
    # Where a comment anchored to master line j should be emitted. If j is a
    # function-name line whose return type sits on the preceding non-blank
    # master line (a multi-line signature), return the return-type index so the
    # comment lands above the whole signature rather than between type and name.
    if j > 0 and '(' in master_lines[j]:
        mb = j - 1
        while mb > 0 and master_lines[mb].strip() == '':
            mb -= 1
        s = master_lines[mb].strip()
        if s and '(' not in s and not s.endswith((';', '{', '}')):
            return mb
    return j

def process_file(path):
    anno_t = git_show(ANNO, path)
    old_t  = git_show(OLD, path)
    new_t  = git_show(MASTER, path)
    if anno_t is None or old_t is None or new_t is None:
        return None
    anno_lines = anno_t.split('\n')
    old_lines  = old_t.split('\n')
    new_lines  = new_t.split('\n')
    # Blank over the WHOLE text so multi-line block comments are handled,
    # then split back into one skeleton line per original line. Trailing
    # whitespace is stripped so a code line with a blanked trailing comment
    # still matches the same code line that has no trailing comment.
    sa = [l.rstrip() for l in blank(path, anno_t).split('\n')]
    so = [l.rstrip() for l in blank(path, old_t).split('\n')]
    sn = [l.rstrip() for l in blank(path, new_t).split('\n')]

    a_gap = leading_gap(sa)      # anno code idx -> preceding comment/blank idxs
    o_gap = leading_gap(so)      # old  code idx -> preceding comment/blank idxs
    a_code = code_indices(sa)
    o_code = code_indices(so)

    a2o = align(sa, so)          # anno code line -> old code line
    o2n = align(so, sn)          # old code line -> new code line

    def sub_old(anno_g, old_g):
        # user annotation lines = anno gap MINUS old's own comment block
        # (matched as a contiguous sequence, so generic lines like " */" are
        # not wrongly removed).
        smg = difflib.SequenceMatcher(None, old_g, anno_g, autojunk=False)
        old_match = set()
        for tag, i1, i2, j1, j2 in smg.get_opcodes():
            if tag == 'equal':
                for d in range(j2 - j1):
                    old_match.add(j1 + d)
        return [anno_g[k] for k in range(len(anno_g))
                if k not in old_match and anno_g[k].strip() != '']

    def anno_comment(ai, oi):
        anno_g = [anno_lines[k] for k in a_gap.get(ai, [])]
        if oi is not None:
            old_g = [old_lines[k] for k in o_gap.get(oi, [])]
            return normalize_comment_block(sub_old(anno_g, old_g))
        return normalize_comment_block([l for l in anno_g if l.strip() != ''])

    # per new-code-line emissions: (leading annotation lines, trailing annotation)
    emit = {}
    dropped_comments = []          # (anno ai, raw gap lines) to re-anchor
    carried_lead = 0; carried_trail = 0; dropped = 0
    for ai in a_code:
        oi = a2o.get(ai)
        if oi is None:
            dropped += 1
            dropped_comments.append((ai, [anno_lines[k] for k in a_gap.get(ai, [])]))
            continue
        nj = o2n.get(oi)
        if nj is None:
            dropped += 1
            dropped_comments.append((ai, [anno_lines[k] for k in a_gap.get(ai, [])]))
            continue
        ann_lines = anno_comment(ai, oi)
        # trailing annotation
        trail = None
        ta = trailing_comment(anno_lines[ai])
        to = trailing_comment(old_lines[oi])
        if ta is not None and ta != to:
            trail = ta
        emit.setdefault(nj, [[], None])
        if ann_lines:
            emit[nj][0] = ann_lines
            carried_lead += len(ann_lines)
        if trail is not None:
            emit[nj][1] = trail
            carried_trail += 1

    # Re-anchor comments whose code line was changed/dropped in the annotated
    # branch (so it has no verbatim line in master) onto the next master code
    # line that still maps. Keeps master code untouched, preserves the comment.
    mapped_nj = {}
    for ai in a_code:
        oi = a2o.get(ai)
        if oi is not None:
            nj = o2n.get(oi)
            if nj is not None:
                mapped_nj[ai] = (nj, oi)          # master line, old line
    mapped_codes = sorted(mapped_nj)
    if dropped_comments and mapped_codes:
        for ai, raw_gap in dropped_comments:
            pos = bisect.bisect_left(mapped_codes, ai)
            if pos < len(mapped_codes):
                nj, oi = mapped_nj[mapped_codes[pos]]
                old_g = [old_lines[k] for k in o_gap.get(oi, [])]
                c_lines = normalize_comment_block(sub_old(raw_gap, old_g))
                if not c_lines:
                    continue
                t = block_start(nj, new_lines)
                if t not in emit:
                    emit[t] = [[], None]
                if not emit[t][0]:
                    emit[t][0] = c_lines
                    carried_lead += len(c_lines)

    out = []
    for j, l in enumerate(new_lines):
        if j in emit:
            for a in emit[j][0]:
                out.append(a)
            t = emit[j][1]
            if t is not None:
                l = l.rstrip() + t
        out.append(l)

    return '\n'.join(out), carried_lead, carried_trail, dropped

def main():
    files = subprocess.check_output(
        ['git', 'diff', '--name-only', OLD, ANNO]).decode('utf-8', 'replace').split()
    targets = [f for f in files if f.startswith('src/') or f.startswith('auto/')]
    tl = tr = td = 0
    for f in targets:
        r = process_file(f)
        if r is None:
            continue
        result, lead, trail, dropped = r
        tl += lead; tr += trail; td += dropped
        full = os.path.join(REPO, f)
        d = os.path.dirname(full)
        if not os.path.isdir(d):
            os.makedirs(d)
        with io.open(full, 'w', encoding='utf-8') as fh:
            fh.write(result)
        print('%-55s lead=%d trail=%d dropped=%d' % (f, lead, trail, dropped))
    print('TOTAL lead=%d trail=%d dropped-blocks=%d files=%d' % (tl, tr, td, len(targets)))

if __name__ == '__main__':
    main()
