#!/usr/bin/env python3
"""Flatten ml-kem-*/encapdecap-tr1.json into flat/encapdecap-tr1.tsv for the
line-based gates (C / Java / Kotlin). The JSON files are the source of truth;
regenerate after any change:  python3 gen_flat_tr1.py

Columns (tab-separated, lowercase hex, "" when not applicable):
  set  kind  tcId  d  z  ek  dk  m  c  k  passed
kind ∈ encaps (ek,m → c,k) | decaps (d,z → ek,dk; c → k) | ekcheck (ek → passed) | dkcheck (dk → passed)
"""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(HERE, 'flat'), exist_ok=True)
lc = lambda s: (s or '').lower()
rows = 0
with open(os.path.join(HERE, 'flat', 'encapdecap-tr1.tsv'), 'w') as f:
    for s in ('ml-kem-512', 'ml-kem-768', 'ml-kem-1024'):
        d = json.load(open(os.path.join(HERE, s, 'encapdecap-tr1.json')))
        for t in d['encapsulation']:
            f.write('\t'.join([s, 'encaps', str(t['tcId']), '', '', lc(t['ek']), '', lc(t['m']), lc(t['c']), lc(t['k']), '']) + '\n'); rows += 1
        for t in d['decapsulation']:
            f.write('\t'.join([s, 'decaps', str(t['tcId']), lc(t['d']), lc(t['z']), lc(t['ek']), lc(t['dk']), '', lc(t['c']), lc(t['k']), '']) + '\n'); rows += 1
        for t in d['encapsulationKeyCheck']:
            f.write('\t'.join([s, 'ekcheck', str(t['tcId']), '', '', lc(t['ek']), '', '', '', '', '1' if t['testPassed'] else '0']) + '\n'); rows += 1
        for t in d['decapsulationKeyCheck']:
            f.write('\t'.join([s, 'dkcheck', str(t['tcId']), '', '', '', lc(t['dk']), '', '', '', '1' if t['testPassed'] else '0']) + '\n'); rows += 1
print('flat/encapdecap-tr1.tsv', rows, 'rows')
