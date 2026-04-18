#!/usr/bin/env python3
"""
Phase 2: Add rich multi-line headers and inline comments to critical functions
in nngine_decompiled.c.backup. Reads annotations from annotations_data.py.
"""
import re, sys
sys.path.insert(0, '/home/mark/git/MediaNavToolbox/analysis')
from annotations_data import RICH_HEADERS, INLINE_COMMENTS, SECTION_BANNERS, DAT_COMMENTS

FILE = "/home/mark/git/MediaNavToolbox/analysis/nngine_decompiled.c.backup"

print(f"Reading {FILE}...")
with open(FILE) as f:
    lines = f.readlines()
total = len(lines)
print(f"{total} lines")

# Build function line index: fname -> line number (0-based)
func_re = re.compile(r'^([A-Za-z_]\S*(?:\s+\S+)*?)\s+(?:__\w+\s+)?([A-Za-z_~][\w:~<>,\s]*?)\s*\(')
func_lines = {}
for i, line in enumerate(lines):
    s = line.rstrip('\n')
    if not s or s[0] in ' \t{}/*#':
        continue
    m = func_re.match(s)
    if m:
        func_lines[m.group(2).strip()] = i

print(f"Indexed {len(func_lines)} functions")

# Phase 1: Replace single-line comments with rich headers
replaced = 0
for fname, header in RICH_HEADERS.items():
    if fname not in func_lines:
        print(f"  WARN: {fname} not found")
        continue
    idx = func_lines[fname]
    # The line before should be the existing single-line comment
    if idx > 0 and lines[idx-1].strip().startswith('/*') and lines[idx-1].strip().endswith('*/'):
        lines[idx-1] = header + '\n'
        replaced += 1
    else:
        # Insert before the function
        lines.insert(idx, header + '\n')
        # Shift all indices after this point
        for fn, li in func_lines.items():
            if li >= idx and fn != fname:
                func_lines[fn] = li + 1
        replaced += 1

print(f"Replaced {replaced} headers")

# Phase 2: Add inline comments within function bodies
# Re-index after header changes
func_lines2 = {}
for i, line in enumerate(lines):
    s = line.rstrip('\n')
    if not s or s[0] in ' \t{}/*#':
        continue
    m = func_re.match(s)
    if m:
        func_lines2[m.group(2).strip()] = i

inlined = 0
for fname, comments in INLINE_COMMENTS.items():
    if fname not in func_lines2:
        continue
    start = func_lines2[fname]
    # Find function end
    brace = 0
    opened = False
    end = start
    for j in range(start, min(start + 800, len(lines))):
        if '{' in lines[j]:
            opened = True
        if opened:
            brace += lines[j].count('{') - lines[j].count('}')
            if brace <= 0:
                end = j
                break

    # Apply inline comments (pattern -> comment)
    for pattern, comment in comments:
        for j in range(start, end + 1):
            if pattern in lines[j] and '/*' not in lines[j].rstrip('\n').split(pattern)[-1]:
                lines[j] = lines[j].rstrip('\n') + f'  {comment}\n'
                inlined += 1
                break  # only first match per pattern

print(f"Added {inlined} inline comments")

# Phase 3: Add DAT_ inline comments throughout the file
dat_count = 0
for dat, comment in DAT_COMMENTS.items():
    # Only annotate first 5 occurrences to avoid bloat
    count = 0
    for i in range(len(lines)):
        if dat in lines[i] and '/*' not in lines[i].rstrip('\n').split(dat)[-1]:
            lines[i] = lines[i].rstrip('\n') + f'  /* {comment} */\n'
            dat_count += 1
            count += 1
            if count >= 3:
                break

print(f"Added {dat_count} DAT_ comments")

# Phase 4: Insert section banners
# Sort by line number descending so inserts don't shift later positions
banner_inserts = []
for fname, banner in SECTION_BANNERS.items():
    if fname in func_lines2:
        # Find the comment line before the function
        idx = func_lines2[fname]
        # Go back to find the start of the comment block
        while idx > 0 and (lines[idx-1].strip().startswith('/*') or lines[idx-1].strip() == ''):
            idx -= 1
        banner_inserts.append((idx, banner))

banner_inserts.sort(key=lambda x: x[0], reverse=True)
for idx, banner in banner_inserts:
    lines.insert(idx, '\n' + banner + '\n\n')

print(f"Inserted {len(banner_inserts)} section banners")

print(f"Writing {FILE}...")
with open(FILE, 'w') as f:
    f.writelines(lines)
print("Done!")
