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

# Classes for rrd data graphing

import logging

import rrdtool

from rrd_fn import RRDFileNamer
from constants import *

class RRDGrapher(RRDFileNamer):
   logger = logging.getLogger()
   log = logger.log
   IMG_FMT = 'PNG'
   TITLE_FMT = '%(ct_str)s on %(ifs)s'
   FN_FMT = '%s_%s_%s_%s.png'
   CT_LABELS = {
      CT_BYTES:'bytes',
      CT_PACKETS:'packets'
   }
   CF = 'AVERAGE'
   def __init__(self, rrd_base_filename, interface_specs, rules, periods, base,
         img_width, img_height, counter_types, ifn_prefix):
      self.rrd_base_filename = rrd_base_filename
      self.interface_specs = interface_specs
      self.rules = rules[:]
      self.rules.reverse()
      self.ct_s = counter_types
      self.periods = periods		# time periods to graph
      self.base = base
      self.img_width = img_width
      self.img_height = img_height
      self.ifn_prefix = ifn_prefix	# prefix for imge files to write
   
   def data_graph(self):
      for ct in self.ct_s:
         for ifs in self.interface_specs:
            for period in self.periods:
               defs = []
               graph_cmds = []
               for (dir_, dir_str) in self.FN_DIR.items():
                  for rule in self.rules:
                     rrd_fn = self.rrd_fn_get(ifs, dir_, ct)
                     vname = '%s_%s_%s' % (ifs,dir_str,rule.ds)
                     vname = vname.replace('+','_')
                     defs.append('DEF:%s=%s:%s:%s' % (vname, rrd_fn, rule.ds, self.CF))
                     if (dir_ == DIR_OUT):
                        # Invert sign for outgoing traffic to graph it below x-axis
                        vname2 = vname + '_'
                        defs.append('CDEF:%s=%s,-1,*' % (vname2,vname))
                        vname = vname2
                     graph_cmds.append('AREA:%s%s' % (vname,rule.color))
         
               ct_str = self.CT_LABELS[ct]
               fn = self.FN_FMT % (self.ifn_prefix, ifs, ct_str, period)
               self.log(20, 'Updating file %r.' % (fn,))
               rrdtool.graph(fn,
                  '-z',
                  '-s', str(-1*period),
                  '-a', self.IMG_FMT,
                  '-b', str(self.base),
                  '-t', self.TITLE_FMT % locals(),
                  '-w', str(self.img_width),
                  '-h', str(self.img_height),
                  *(defs + graph_cmds))

