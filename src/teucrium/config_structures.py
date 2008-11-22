#!/usr/bin/env python
#Copyright 2008 Sebastian Hagen
# This file is part of teucrium.
#
# teucrium is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# teucrium is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import os

POS_LOCAL = 0
POS_REMOTE = 1
DIR_IN = 0
DIR_OUT = 1

class LRPort:
   """Abstract baseclass for LocalPort, RemotePort"""
   FMT_SRC = '--sport %d'
   FMT_DST = '--dport %d'
   def __init__(self, port):
      self.port = port
      assert(self.POS in (POS_LOCAL, POS_REMOTE))
   
   def xt_ms_in(self):
      """Return XT matchstring for incoming traffic"""
      if (self.POS == POS_LOCAL):
         return self.FMT_DST % (self.port,)
      return self.FMT_SRC % (self.port,)
   
   def xt_ms_out(self):
      """Return XT matchstring for outgoing traffic"""
      if (self.POS == POS_LOCAL):
         return self.FMT_SRC % (self.port,)
      return self.FMT_DST % (self.port,)
   

class LocalPort(LRPort):
   """Specify port/portrange on *this* host"""
   POS = POS_LOCAL

class RemotePort(LRPort):
   """Specify port/portrange on *remote* host"""
   POS = POS_REMOTE

class XTRule:
   XT_ARG_FMT = '%s -m comment --comment %s %s'
   DIRS = {
      DIR_IN: 'xt_ms_in',
      DIR_OUT:'xt_ms_out'
   }
   def __init__(self, ds, matches, id=None, rule_id_get=None):
      """
      ds: rrd datasource to dump data from this counter into
      matches: XT matches for this rule
      id: string to use for identifying this rule in netfilter chain
      """
      if (isinstance(matches, str)):
         raise ValueError('Invalid matches sequence %r; did you forget a\
            container?' % (matches,))
      self.ds = ds
      self.matches = matches
      if (id is None):
         id = rule_id_get()
      self.id = id
   
   @classmethod
   def match2string(cls, match, dir_):
      """Convert a match to a IPT match string."""
      methname = cls.DIRS[dir_]
      if (hasattr(match, methname)):
         return getattr(match,methname)()
      return str(match)
   
   def xt_argstring_get(self, chain, dir_):
      return self.XT_ARG_FMT % (chain, self.id, ' '.join([self.match2string(m, dir_) for m in self.matches]))

class XTCall:
   logger = logging.getLogger('XTCall')
   log = logger.log
   def __init__(self, xt_binary, tablename, argstring, errors_ignore=False):
      self.xt_binary = xt_binary
      self.tablename = tablename
      self.argstring = argstring
      self.errors_ignore = errors_ignore
   
   def callstring_get(self):
      rv = '%s -t %s %s' % (self.xt_binary, self.tablename, self.argstring)
      if (self.errors_ignore):
         rv += ' 2>/dev/null'
      return rv
   
   def xt_call(self):
      cs = self.callstring_get()
      os.log(20, 'Executing %r.' % (cs,))
      rcode = os.system(cs)
      if (rv and not self.errors_ignore):
         raise StandardError('os.system(%s) failed. rcode: %r' % (cs,rcode))


class XTTrafficSpec:
   """Abstract baseclass for *TTrafficSpec classes"""
   DIRS = {
      DIR_IN: ('in', '-i'),
      DIR_OUT: ('out', '-o')
   }
   RULE_ID_FMT = 'teuc_%d'
   CHAIN_FMT_BASE = 'teuc_%s'
   CHAIN_FMT = CHAIN_FMT_BASE % ('%s_%s',)
   def __init__(self, tablename, interface_specs):
      if not (hasattr(self, 'xt_binary')):
         raise StandardError('%r should not be instantiated; use a subclass' % (self.__class__))
      self.rules = []
      self.rule_ids = set()
      self.rule_idnum_last = 0
      self.interface_specs = interface_specs
      self.tablename = tablename
   
   def rule_id_get(self):
      rule_id = self.RULE_ID_FMT % (self.rule_idnum_last,)
      while (rule_id in self.rule_ids):
         self.rule_idnum_last += 1
         rule_id = self.RULE_ID_FMT % (self.rule_idnum_last,)
      self.rule_idnum_last += 1
      return rule_id
   
   def rule_add(self, *args, **kwargs):
      kwargs['rule_id_get'] = self.rule_id_get
      rule = XTRule(*args, **kwargs)
      self.rules.append(rule)
      self.rule_ids.add(rule.id)
   
# ---------------------------------------------------------------- IPT output
   def xt_callstring_chainmake_get(self, chainname, flush=True):
      rv = [self.xtcall('-N %s' % (chainname,), errors_ignore=True)]
      if (flush):
         rv.append(self.xtcall('-F %s' % (chainname,)))
      return rv
   
   def get_dirname(self, dir_):
      return self.DIRS[dir_][0]
   
   def get_dirxtmatch(self, dir_):
      return self.DIRS[dir_][1]
   
   def xtcall(self, *args, **kwargs):
      return XTCall(self.xt_binary, self.tablename, *args, **kwargs)
   
   def xtcall_countrule(self, argstring, *args, **kwargs):
      return [self.xtcall('-D ' + argstring, True),
      self.xtcall('-A ' + argstring, *args, **kwargs)]
   
   def xt_dirifaces_get(self):
      for iface_spec in self.interface_specs:
         for dir_ in self.DIRS:
            yield (iface_spec, dir_)
   
   def xt_callstrings_get(self):
      rv = []
      for dir_ in self.DIRS:
         rv += self.xt_callstring_chainmake_get(self.CHAIN_FMT_BASE % (self.get_dirname(dir_)), flush=False)
      
      for (iface_spec, dir_) in self.xt_dirifaces_get():
         chainname = self.CHAIN_FMT % (iface_spec, self.get_dirname(dir_))
         rv += self.xt_callstring_chainmake_get(chainname)
         rv += (self.xtcall_countrule('%s %s %s -j %s' % (self.CHAIN_FMT_BASE % (
            self.get_dirname(dir_),), self.get_dirxtmatch(dir_), iface_spec,
            chainname)))
            
         for rule in self.rules:
            rv += self.xtcall_countrule(rule.xt_argstring_get(chainname, dir_))
      
      return rv
   
# ---------------------------------------------------------------- xtables reader output
   


class IPTTrafficSpec(XTTrafficSpec):
   xt_binary = 'iptables'

class IP6TTrafficSpec(XTTrafficSpec):
   xt_binary = 'ip6tables'

# Arptables doesn't support --comment, hence we don't support arptables.

if (__name__ == '__main__'):
   # Here there be self-tests.
   import pprint
   iptts = IPTTrafficSpec('filter', ('eth+', 'ppp+', 'tun0', 'tun1'))
   iptts.rule_add('httpd', ('-p tcp', LocalPort(80)))
   iptts.rule_add('http_client', ('-p tcp', RemotePort(80)))
   iptts.rule_add('tcp_other', ('-p tcp',))
   iptts.rule_add('dns_client', ('-p udp', LocalPort(53)))
   iptts.rule_add('udp_other', ('-p udp',))
   pprint.pprint([xtc.callstring_get() for xtc in iptts.xt_callstrings_get()])
   
   print('=== All tests passed. ===')

