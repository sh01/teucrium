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
import os, os.path

from gonium.linux.xtables import XTablesIP, XTablesIP6

from constants import *
from rrd_tc import RRDTrafficCounter
from rrd_creator import RRASpec, RRDCreator
from rrd_grapher import RRDGrapher

POS_LOCAL = 0
POS_REMOTE = 1
DIR_IN = 0
DIR_OUT = 1

class ConfigError(StandardError):
   pass

class LRPort:
   """Abstract baseclass for LocalPort, RemotePort"""
   FMT_SRC = '--sport %s'
   FMT_DST = '--dport %s'
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

class LRMultiport:
   FMT_SRC = '--sports %s'
   FMT_DST = '--dports %s'

class LocalPort(LRPort):
   """Specify port/portrange on *this* host"""
   POS = POS_LOCAL

class LocalPorts(LRMultiport, LocalPort):
   pass

class RemotePort(LRPort):
   """Specify port/portrange on *remote* host"""
   POS = POS_REMOTE

class RemotePorts(LRMultiport, RemotePort):
   pass

class XTRule:
   XT_ARG_FMT = '%s -m comment --comment %s %s'
   DIRS = {
      DIR_IN: 'xt_ms_in',
      DIR_OUT:'xt_ms_out'
   }
   def __init__(self, ds, matches, id=None, rule_id_get=None, color='',
          target='RETURN'):
      """
      ds: rrd datasource to dump data from this counter into
      matches: XT matches for this rule
      id: string to use for identifying this rule in netfilter chain
      (if not specified, use rule_id_get())
      color: rrd color to use for graphing traffic counted by this rule
      target: NF targeto associate with rule; defaults to 'RETURN'
      """
      if (isinstance(matches, str)):
         raise ValueError('Invalid matches sequence %r; did you forget a\
            container?' % (matches,))
      
      if (color != ''):
         if (not color.startswith('#')):
            raise ValueError('Invalid colorspec %r; needs to be empty or start with "#".')
         if (len(color) != 7):
            raise ValueError('Invalid colorspec %r; needs to be 7 chars in length.')
         try:
            int(color[1:],16)
         except ValueError:
            raise ValueError('Invalid colorspec %r; 6 last chars need to be hexadecimal digits.')
      
      self.ds = ds
      self.matches = matches
      if (id is None):
         id = rule_id_get()
      self.id = id
      self.color = color
      self.target = target
   
   @classmethod
   def match2string(cls, match, dir_):
      """Convert a match to a IPT match string."""
      methname = cls.DIRS[dir_]
      if (hasattr(match, methname)):
         return getattr(match,methname)()
      return str(match)
   
   def xt_argstring_get(self, chain, dir_):
      argstring = ' '.join([self.match2string(m, dir_) for m in self.matches])
      if (self.target):
         argstring += ' -j %s' % (self.target,)
      return self.XT_ARG_FMT % (chain, self.id, argstring)

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
      self.log(20, 'Executing %r.' % (cs,))
      rcode = os.system(cs)
      if (rcode and not self.errors_ignore):
         raise StandardError('os.system(%s) failed. rcode: %r' % (cs,rcode))


class XTTrafficRules:
   """Abstract baseclass for *TTrafficRules classes"""
   DIRS = {
      DIR_IN: ('in', '-i'),
      DIR_OUT: ('out', '-o')
   }
   RULE_ID_FMT = 'teuc_%d'
   CHAIN_FMT_BASE = 'teuc_%s'
   CHAIN_FMT = CHAIN_FMT_BASE % ('%s_%s',)
   
   # Which non-teuc chains to hook into to get traffic
   EXT_CHAINS = {
       'filter':{
          DIR_IN: ('INPUT', 'FORWARD'),
          DIR_OUT: ('OUTPUT', 'FORWARD'),
       },
       'mangle':{
          DIR_IN: ('PREROUTING',),
          DIR_OUT: ('POSTROUTING',)
       },
       'nat': {
          DIR_IN: ('PREROUTING',),
          DIR_OUT: ('POSTROUTING',)
       }
   }
   
   def __init__(self, tablename, interface_specs, step=2,
         rrddb_base_filename='teucriumdb',
         graph_base_filename='teucrium', graph_periods=(600,3600,86400),
         graph_counter_types=(CT_BYTES,CT_PACKETS), graph_base=1024,
         graph_img_width=512, graph_img_height=256,
         rrd_heartbeat=None, rrd_max='U',
         rra_specs=None):
      """Initialize instance.
      
      Arguments:
      tablename: xt table to use; e.g. 'filter', 'mangle' or 'nat'
      interface_specs: sequence of interface-strings to match against; e.g. ('eth+', 'ppp0')
      step: RRD step value (in seconds)
      rrddb_base_filename: Filename prefix to use for rrd files
      
      # The following parameters are only relevant for graphing mode
      graph_base_filename: filename prefix for generated images
      graph_periods: lengths of time periods to graph (in seconds)
      graph_counter_types: counter types (CT_BYTES/CT_PACKETS) to graph
      graph_base: rrdgraph 'base' argument (typically 1000 or 1024)
      graph_img_width: graph width
      graph_img_height: graph height
      
      # The following parameters are only relevant for rrd db creation
      rrd_heartbeat: RRD heartbeat (in seconds); defaults to step
      rrd_max: maximum for rrd DS
      rra_specs: initial RRA spec list; note that these can also be added after
            instantiation by calling the rra_add() method
      """
      if not (hasattr(self, 'xt_binary')):
         raise StandardError('%r should not be instantiated; use a subclass' % (self.__class__))
      
      if not (tablename in self.EXT_CHAINS):
         raise ValueError("Table %r isn't supported." % (tablename,))
      
      if (rrd_heartbeat is None):
         rrd_heartbeat = step
      if (rra_specs is None):
         rra_specs = []
      
      self.rules = []
      self.rule_ids = set()
      self.rule_idnum_last = 0
      self.interface_specs = interface_specs
      self.tablename = tablename
      self.step = step
      self.rrddb_base_filename = rrddb_base_filename
      
      self.rrd_heartbeat = rrd_heartbeat
      self.rrd_max = rrd_max
      self.rra_specs = rra_specs
      
      self.graph_fnprefix = graph_base_filename
      self.graph_periods = graph_periods
      self.graph_counter_types = graph_counter_types
      self.graph_base = graph_base
      self.graph_img_width = graph_img_width
      self.graph_img_height = graph_img_height
# ---------------------------------------------------------------- configuration interface
   def rule_add(self, *args, **kwargs):
      """Add traffic counting rule to this instance. See XTRule.__init__() for
         list and explanation of arguments."""
      kwargs['rule_id_get'] = self.rule_id_get
      rule = XTRule(*args, **kwargs)
      self.rules.append(rule)
      self.rule_ids.add(rule.id)

   def rra_add(self, *args, **kwargs):
      """Add RRA spec; this is only relevant for rrdcreate() mode. Arguments
         are as to rrdtool::rrdcreate::RRA. (1.3.1)"""
      self.rra_specs.append(RRASpec(*args, **kwargs))

# ---------------------------------------------------------------- Internal interface
   def rule_id_get(self):
      rule_id = self.RULE_ID_FMT % (self.rule_idnum_last,)
      while (rule_id in self.rule_ids):
         self.rule_idnum_last += 1
         rule_id = self.RULE_ID_FMT % (self.rule_idnum_last,)
      self.rule_idnum_last += 1
      return rule_id

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
         chain = self.CHAIN_FMT_BASE % (self.get_dirname(dir_))
         rv += self.xt_callstring_chainmake_get(chain, flush=False)
      
      for (iface_spec, dir_) in self.xt_dirifaces_get():
         chainname = self.CHAIN_FMT % (iface_spec, self.get_dirname(dir_))
         rv += self.xt_callstring_chainmake_get(chainname)
         rv += (self.xtcall_countrule('%s %s %s -j %s' % (self.CHAIN_FMT_BASE % (
            self.get_dirname(dir_),), self.get_dirxtmatch(dir_), iface_spec,
            chainname)))
            
         for rule in self.rules:
            rv += self.xtcall_countrule(rule.xt_argstring_get(chainname, dir_))

      for dir_ in self.DIRS:
         tgt_chain = self.CHAIN_FMT_BASE % (self.get_dirname(dir_))
         src_chains = self.EXT_CHAINS[self.tablename][dir_]
         for src_chain in src_chains:
            rv += [self.xtcall('-D %s -j %s' % (src_chain,tgt_chain), errors_ignore=True),
               self.xtcall('-I %s 1 -j %s' % (src_chain,tgt_chain))]
      
      return rv
   
   def xt_call(self):
      for cmd in self.xt_callstrings_get():
         cmd.xt_call()
      
   
# ---------------------------------------------------------------- rrd tc output
   def rrdtc_param_get(self):
      rules2ds = {}
      for rule in self.rules:
         rules2ds[rule.id] = rule.ds
      
      chain2diriface = {}
      
      for (iface_spec, dir_) in self.xt_dirifaces_get():
         chainname = self.CHAIN_FMT % (iface_spec, self.get_dirname(dir_))
         chain2diriface[chainname] = (iface_spec, dir_)
      
      return (rules2ds, chain2diriface)
   
   def rrdtc_build(self, ed):
      (rules2ds, chain2diriface) = self.rrdtc_param_get()
      return RRDTrafficCounter.build_with_xtp(ed, self.step, self.xt_cls(),
         (self.tablename,), self.rrddb_base_filename, rules2ds, chain2diriface)
   
# ---------------------------------------------------------------- RRDCreator output
   def rrdc_build(self):
      ds_l = [rule.ds for rule in self.rules]
      ds_l.sort()
      return RRDCreator(self.rrddb_base_filename, self.interface_specs, ds_l,
         self.rra_specs, self.step, self.rrd_heartbeat, self.rrd_max)
# ---------------------------------------------------------------- RRDGrapher output
   def rrdg_build(self):
      return RRDGrapher(self.rrddb_base_filename, self.interface_specs,
         self.rules, self.graph_periods, self.graph_base, self.graph_img_width,
         self.graph_img_height, self.graph_counter_types, self.graph_fnprefix)


class IPTTrafficRules(XTTrafficRules):
   xt_binary = 'iptables'
   xt_cls = XTablesIP

class IP6TTrafficRules(XTTrafficRules):
   xt_binary = 'ip6tables'
   xt_cls = XTablesIP6

class TeucriumConfig:
   """Teucrium config file reader"""
   content = ('IPTTrafficRules', 'IP6TTrafficRules', 'LocalPort', 'RemotePort',
      'LocalPorts', 'RemotePorts', 'CT_BYTES', 'CT_PACKETS')
   cfd_global = '/etc/teucrium/'
   cfd_user = '~/.teucrium/'
   cfn_name = 'teucrium.conf'
   logger = logging.getLogger('TeucriumConfig')
   log = logger.log
   def __init__(self):
      self.xtrs = []
   def xtr_register(self, xtr):
      self.xtrs.append(xtr)
   def file_read(self, filename):
      """Read config from file with specified name"""
      g = {}
      for s in self.content:
         g[s] = globals()[s]
      
      g['xtr_register'] = self.xtr_register
      execfile(filename, g)
   
   def cfd_user_get(self):
      return os.path.expanduser(self.cfd_user)
   
   def config_read(self):
      """Choose and read config file"""
      for cf_dir in (self.cfd_user_get(), self.cfd_global):
         cfn = os.path.join(cf_dir, self.cfn_name)
         self.log(20, 'Trying to read config file %r ...' % (cfn,))
         try:
            os.chdir(cf_dir)
            self.file_read(cfn)
         except OSError:
            pass
         else:
            self.log(20, 'Got config from %r.' % (cfn,))
            break
      else:
         raise ConfigError('No valid config file found.')

# Arptables doesn't support --comment, hence we don't support arptables.

if (__name__ == '__main__'):
   # Here there be self-tests.
   import pprint
   ipttr = IPTTrafficRules('filter', ('eth+', 'ppp+', 'tun0', 'tun1'))
   ipttr.rule_add('httpd', ('-p tcp', LocalPort(80)))
   ipttr.rule_add('http_client', ('-p tcp', RemotePort(80)))
   ipttr.rule_add('tcp_other', ('-p tcp',))
   ipttr.rule_add('dns_client', ('-p udp', LocalPort(53)))
   ipttr.rule_add('udp_other', ('-p udp',))
   print('=== XT callstrings: ===')
   pprint.pprint([xtc.callstring_get() for xtc in ipttr.xt_callstrings_get()])
   pprint.pprint(ipttr.rrdc_build())
   print('=== All tests passed. ===')

