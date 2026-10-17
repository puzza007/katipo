#!/usr/bin/env python3
"""Diff TLC's state graph of KatipoFlow.tla against the Lean model's.

usage: crosscheck_flow.py TLC.dot LEAN.txt
TLC.dot:  tlc -deadlock -config KatipoFlow.cfg -dump dot,actionlabels TLC.dot KatipoFlow.tla
LEAN.txt: lake env lean --run scripts/FlowGraph.lean > LEAN.txt
Both sides are canonicalised to sorted `var=value` strings; self-loops
(stuttering) are ignored. Exit 1 on any difference.
"""
import re
import sys


def canon_tlc(label):
    label = label.replace('\\"', '"')
    fields = {}
    for line in label.split('\\n'):
        m = re.match(r'/\\\\ (\w+) = (.*)$', line.strip())
        if m:
            fields[m.group(1)] = m.group(2)
    return ';'.join(f'{k}={fields[k]}' for k in sorted(fields))


def load_tlc(path):
    text = open(path).read()
    nodes, init = {}, None
    for m in re.finditer(r'^(-?\d+) \[label="(.*?)"(,tooltip="[^"]*(?:\\"[^"]*)*")?(,style = filled)?\]', text, re.M):
        nodes[m.group(1)] = canon_tlc(m.group(2))
        if m.group(4):
            init = nodes[m.group(1)]
    edges = set()
    for m in re.finditer(r'^(-?\d+) -> (-?\d+) ', text, re.M):
        a, b = nodes[m.group(1)], nodes[m.group(2)]
        if a != b:
            edges.add((a, b))
    return set(nodes.values()), edges, init


def canon_lean(s):
    return ';'.join(sorted(s.split(';')))


def load_lean(path):
    nodes, edges, init = set(), set(), None
    for line in open(path):
        line = line.rstrip('\n')
        if line.startswith('I '):
            init = canon_lean(line[2:])
            nodes.add(init)
        elif line.startswith('E '):
            a, b = line[2:].split(' => ')
            a, b = canon_lean(a), canon_lean(b)
            nodes.update((a, b))
            edges.add((a, b))
    return nodes, edges, init


tn, te, ti = load_tlc(sys.argv[1])
ln, le, li = load_lean(sys.argv[2])
print(f'TLC : {len(tn)} states, {len(te)} edges')
print(f'Lean: {len(ln)} states, {len(le)} edges')
bad = 0
for name, a, b in [('states only in TLC', tn, ln), ('states only in Lean', ln, tn),
                   ('edges only in TLC', te, le), ('edges only in Lean', le, te)]:
    d = a - b
    if d:
        bad = 1
        print(f'{name}: {len(d)}')
        for x in list(d)[:3]:
            print('   ', x)
if ti != li:
    bad = 1
    print('initial states differ')
print('IDENTICAL' if not bad else 'MISMATCH')
sys.exit(bad)
