#!/usr/bin/env python
from __future__ import print_function
import tempfile
import sys
import subprocess
import os
import logging
from lxml import etree as ET
from functools import wraps

# Init logging

logging.basicConfig()
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

def log(text):
  def outer_wrap(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
      result = f(*args, **kwargs)
      logger.info('%s: %s'%(text, result))
      return result
    return wrapper
  return outer_wrap

# Tools

def execute(cmd):
  proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  return proc.communicate()[0].strip()

### Cipher utils

class Cipher(object):
  def __init__(self, node):
    self.node = node
    self.name = node.attrib['name']
    self.protocol = node.getparent().getparent().attrib['title'].split(' ', 1)[0].replace('_', '.')
  def is_anonymous_diffie_hellman(self):
    return 'ADH' in self.name 
  def is_export_suite(self):
    return 'EXPORT' in self.name
  def bitsize(self):
    if not 'keySize' in self.node.attrib:
      return None
    bits = self.node.attrib['keySize']
    if bits == 'Anon': return 0
    return int(bits.split(' ')[0])

def get_ciphers(tree, unique=True):
  ciphers = []
  names = set()
  for node in tree.findall('.//acceptedCipherSuites/cipherSuite'):
    cipher = Cipher(node)
    if unique:
      if cipher.name in names: continue
      else: names.add(cipher.name)
    ciphers.append(cipher)
  return ciphers

### Scorer base

class Scorer(object):
  def __init__(self):
    pass
  def describe(self, why, score):
    logger.info('%s: %d'%(why, score))
    return score

### Check cipher

class CipherScorer(Scorer):
  def __init__(self, tree):
    self.tree = tree
    self.ciphers = get_ciphers(tree)
    super(CipherScorer, self).__init__()
  @staticmethod
  def bit_score(bits):
    if bits == 0: return 0
    elif 0 < bits < 128: return 20
    elif 128 <= bits < 256: return 80
    else: return 100
  @log('Total cipher score')
  def score(self):
    if len(self.ciphers) == 0:
      raise Exception('No ciphers')
    weakest = self.describe('Weakest cipher bitsize', min([c.bitsize() for c in self.ciphers]))
    strongest = self.describe('Strongest cipher bitsize', max([c.bitsize() for c in self.ciphers]))
    return (CipherScorer.bit_score(weakest) + CipherScorer.bit_score(strongest)) / 2.0

### Rate protocol

class ProtocolScorer(Scorer):
  def __init__(self, tree):
    self.tree = tree
    self.ciphers = get_ciphers(tree, unique=False)
    super(ProtocolScorer, self).__init__()
  @staticmethod
  def score_protocol_name(name):
    if name == 'SSLV2': return 0
    elif name == 'SSLV3': return 80
    elif name == 'TLSV1': return 90
    elif name == 'TLSV1.1': return 95
    elif name == 'TLSV1.2': return 100
  @log('Total protocol score')
  def score(self):
    if len(self.ciphers) == 0:
      raise Exception('No ciphers accepted')
    names = set([c.protocol for c in self.ciphers])
    weakest = min([ProtocolScorer.score_protocol_name(c.protocol) for c in self.ciphers])
    strongest = max([ProtocolScorer.score_protocol_name(c.protocol) for c in self.ciphers])
    logger.info('Weakest protocol score: %s'%weakest)
    logger.info('strongest protocol score: %s'%strongest)
    return (weakest + strongest) / 2.0

### Rate key exchange

class KeyExchangeScorer(Scorer):
  def __init__(self, tree):
    self.tree = tree
    self.ciphers = get_ciphers(tree, unique=False)
    super(KeyExchangeScorer, self).__init__()
  def cert(self):
    try:
      return self.tree.find('.//target/certinfo/certificate/asPEM').text
    except Exception as e:
      return None
  @log('Public key size')
  def get_key_size(self):
    return int(self.tree.find('.//publicKeySize').text.split(' ')[0].strip())
  @log('Has anonymous Diffie-Hellman suite')
  def has_anonymous_diffie_hellman(self):
    return any([c.is_anonymous_diffie_hellman() for c in self.ciphers])
  @log('Has EXPORT key exchange suite')
  def has_export_suite(self):
    return any([c.is_export_suite() for c in self.ciphers])
  @log('Is blacklisted (weak) key')
  def is_blacklisted_key(self):
    path = None
    try:
      with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
        f.write(self.cert())
      return execute("cat %s | openssl-vulnkey -"%path)[0:3].lower() != 'not'
    finally:
      if path is not None: os.unlink(path) 
  @log('Total key exchange score')
  def score(self):
    if self.is_blacklisted_key(): return self.describe('Blacklisted key', 0)
    if self.has_anonymous_diffie_hellman(): return self.describe('Anonymous Diffie-Hellman', 0)
    if self.has_export_suite(): return self.describe('Export key exchange suite', 40)
    key_size = self.get_key_size()
    if key_size < 512: return self.describe('Keysize < 512 bits', 20) 
    elif key_size < 1024: return self.describe('Keysize < 1024 bits', 40)
    elif key_size < 2048: return self.describe('Keysize < 2048 bits', 80)
    elif key_size < 4096: return self.describe('Keysize < 4096 bits', 90)
    else: return self.describe('Keysize >= 4096 bits', 100)

### Rate cert

class CertificateScorer(Scorer):
  def __init__(self, tree):
    self.tree = tree
    super(CertificateScorer, self).__init__()
  @log('Hostname is valid')
  def hostname_valid(self):
    node = self.tree.find('.//hostnameValidation')
    return node is not None and node.attrib['certificateMatchesServerHostname'] == 'False'
  @log('Certificate is valid and issued by trusted CA')
  def is_valid(self):
    '''
    Sort-of a catch-all test for many of the other tests here
    '''
    node = self.tree.find('.//pathValidation')
    return node is not None and node.attrib['validationResult'] == 'ok'
  @log('Self-signed certificate')
  def is_self_signed(self):
    node = self.tree.find('.//pathValidation')
    return node is not None and node.attrib['validationResult'] == 'self signed certificate'
  @log('Is insecure signature')
  def is_insecure_signature(self):
    node = self.tree.find('.//signatureAlgorithm')
    return node is not None and node.text.lower() in ['md2', 'md5']

### Process

def process_report(path, strict=False):
  with open(path) as f:
    data = f.read()
  tree = ET.fromstring(data)
  error = tree.find('.//invalidTarget')
  if error is not None:
    return (error.text, None, error.attrib['error'])
  host = tree.find('.//target').attrib['host']
  cert = CertificateScorer(tree)
  if strict:
    if not cert.hostname_valid():
      return (host, 0, 'invalid hostname')
  if not cert.is_valid():
      return (host, 0, 'untrusted cert')
  if cert.is_insecure_signature():
      return (host, 0, 'insecure signature')
  protocol = ProtocolScorer(tree)
  p_score = protocol.score()
  kx = KeyExchangeScorer(tree)
  kx_score = kx.score()
  cipher = CipherScorer(tree)
  c_score = cipher.score()
  return (
    host,
    0.3 * p_score +
    0.3 * kx_score + 
    0.4 * c_score,
    'Protocol: %s, Key exchange: %s, Cipher: %s'%(p_score, kx_score, c_score)
  )

def main(path):
  host,score,description = process_report(path)
  print('%s\t%s\t%s'%(host,score,description))

if __name__ == '__main__':
  sys.exit(main(*sys.argv[1:]))
