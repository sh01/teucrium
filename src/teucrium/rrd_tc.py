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

import os

import rrdtool
try:
   from gonium.linux.xtables import XTablesPoller
except ImportError:
   pass

from constants import CT_BYTES, CT_PACKETS
from rrd_fn import RRDFileNamer

class RRDTrafficCounter(RRDFileNamer):
   def __init__(self, rrd_base_filename, rules2ds, chain2diriface):
      self.rrd_base_filename = rrd_base_filename
      self.rules2ds = rules2ds
      self.chain2diriface = chain2diriface
   
   @classmethod
   def build_with_xtp(cls, ed, interval, xt, tables, *args, **kwargs):
      xtp = XTablesPoller(ed, interval, xt, tables)
      self  = cls(*args, **kwargs)
      self.xtp = xtp
      xtp.em_xtentries.EventListener(self.xtp_data_process)
   
   def rrd_update(self, iface, dir_, ds_l, cbytes_l, cpackets_l):
      for (cl, ct) in ((cbytes_l, CT_BYTES), (cpackets_l, CT_PACKETS)):
         target_fn = self.rrd_fn_get(iface, dir_, ct)
         rrdtool.update(target_fn, '-t', ':'.join(ds_l), ':'.join([str(e) for e in cl]))
   
   def xtp_data_process(self, event_listener, xtgec):
      chain_valid = False
      tss = str(int(xtgec.ts_get()))
      for rule in xtgec.xtge.entries:
         if (rule.get_target_str() == 'ERROR'):
            if ((chain_valid is True) and ds_l):
               self.rrd_update(iface, dir_, ds_l, cbytes_l, cpackets_l)
            chain = rule.get_chain_name()
            try:
               (iface, dir_) = self.chain2diriface[chain]
            except KeyError:
               chain_valid = False
               continue
            chain_valid = True
            ds_l = []
            cbytes_l = [tss]
            cpackets_l = [tss]
         
         if (chain_valid is False):
            # Not a teucrium counting chain
            continue
         
         # To be robust, we can't assume anything about the rule until we
         # verify it. This means there's a lot of ways for this to fail.
         try:
            match = rule.matches[0]
         except IndexError:
            continue
         if (match.name != 'comment'):
            continue

         try:
            ds = self.rules2ds[match.data_get_str()]
         except KeyError:
            continue
         
         ds_l.append(ds)
         cbytes_l.append(rule.counter_bytes)
         cpackets_l.append(rule.counter_packets)
      
      if ((chain_valid is True) and ds_l):
         self.rrd_update(iface, dir_, ds_l, cbytes_l, cpackets_l)

