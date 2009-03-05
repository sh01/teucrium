#!/usr/bin/env python
#Copyright 2008, 2009 Sebastian Hagen
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

try:
   from gonium.linux.xtables import XTablesPoller
except ImportError:
   pass

from gonium.fd_management import CHILD_REACT_KILL

from constants import CT_BYTES, CT_PACKETS
from rrd_fn import RRDFileNamer

class RRDTrafficCounter(RRDFileNamer):
   logger = logging.getLogger('RRDTrafficCounter')
   log = logger.log
   def __init__(self, ed, rrd_base_filename, rules2ds, chain2diriface, commit_interval):
      self.ed = ed
      self.rrd_base_filename = rrd_base_filename
      self.rules2ds = rules2ds
      self.chain2diriface = chain2diriface
      self.commit_interval = commit_interval
      self.commit_index = 0
      self.output_cache = {}
      self.rrd_child = None
      self.rrd_line_cache = []
   
   def rrd_child_spawn(self):
      if not (self.rrd_child is None):
         raise StandardError('I already have an active rrd_child: %r' % self.rrd_child)
      self.rrd_child = self.ed.ChildRunnerPopen4(('rrdtool', '-'),
         self.child_termination_process, finish=CHILD_REACT_KILL,
         input_handler=self.child_input_process)
   
   def child_input_process(self, child, fd):
      lines = child.buffers_input[fd].split('\n')
      child.buffers_input[fd] = lines[-1]
      del(lines[-1])
      idx_start = 0
      for i in range(len(lines)):
         line = lines[i]
         if (line.startswith('OK')):
            if (self.rrd_line_cache):
               del(self.rrd_line_cache[:])
            idx_start = i+1
            self.log(20, 'Sucessfully executed rrd command: %r' % (line,))
            continue
         if (line.startswith('ERROR')):
            error_lines = self.rrd_line_cache + lines[idx_start:i+1]
            self.log(38, 'rrdtool error: %r' % '\n'.join(error_lines))
            idx_start = i+1
            if (self.rrd_line_cache):
               del(self.rrd_line_cache[:])
            continue
         if (line.startswith('For more information read the RRD manpages')):
            self.log(40, 'Noticed rrdtool syntax error!')
      
      self.rrd_line_cache.extend(lines[idx_start:])
   
   def child_termination_process(self, child, return_code, exit_status):
      self.log(26, '%r notes termination of rrdtool child process RC: %r ES:'
         '%r output: %r.' % (self,return_code, exit_status))
      self.rrd_child = None
      self.rrd_line_cache = []
   
   def rrdfiles_update(self, fn, val_seq):
      if (self.rrd_child is None):
         self.rrd_child_spawn()
      
      # Using full python string escape sequences isn't *exactly* correct, but
      # as long as people don't try to deliberately mess up their own setup,
      # it shouldn't cause any problems.
      self.rrd_child.send_data('update %r -t %r %s\n' % (fn, self.DS_RAW,
         ' '.join('%s:%s' % (tss, val) for (tss,val) in val_seq)))
   
   @classmethod
   def build_with_xtp(cls, ed, interval, xt, tables, *args, **kwargs):
      xtp = XTablesPoller(ed, interval, xt, tables)
      self = cls(ed, *args, **kwargs)
      self.xtp = xtp
      xtp.em_xtentries.EventListener(self.xtp_data_process)
      # Write buffered data on shutdown
      ed.Timer(ed.ts_omega, self.rrd_data_commit, self, ts_relative=False)
   
   def rrd_data_commit(self):
      for ((iface, dir_, ds, ct), val_list) in self.output_cache.items():
         target_fn = self.rrd_fn_get(iface, dir_, ct, ds)
         self.rrdfiles_update(target_fn, val_list)
         del(val_list[:])
   
   def rrd_data_queue(self, iface, dir_, ds_l, tss, cbytes_l, cpackets_l):
      for (ds, bc, pc) in zip(ds_l, cbytes_l, cpackets_l):
         for (c, ct) in ((bc, CT_BYTES), (pc, CT_PACKETS)):
            val_list = self.output_cache.get((iface, dir_, ds, ct),None)
            if (val_list is None):
               val_list = self.output_cache[(iface, dir_, ds, ct)] = []
            val_list.append((tss, c))
      
   def xtp_data_process(self, event_listener, xtgec):
      chain_valid = False
      tss = str(int(xtgec.ts_get()))
      for rule in xtgec.xtge.entries:
         if (rule.get_target_str() == 'ERROR'):
            if ((chain_valid is True) and ds_l):
               self.rrd_data_queue(iface, dir_, ds_l, tss, cbytes_l, cpackets_l)
            chain = rule.get_chain_name()
            try:
               (iface, dir_) = self.chain2diriface[chain]
            except KeyError:
               chain_valid = False
               continue
            chain_valid = True
            ds_l = []
            cbytes_l = []
            cpackets_l = []
         
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
         self.rrd_data_queue(iface, dir_, ds_l, tss, cbytes_l, cpackets_l)
      
      self.commit_index = (self.commit_index + 1) % self.commit_interval
      if (not self.commit_index):
         self.rrd_data_commit()

