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

# Classes for executing rrdcreate commands

import logging
import os, os.path

import rrdtool

from rrd_fn import RRDFileNamer


class RRASpec:
   def __init__(self, cf, xff, steps, rows):
      self.cf = cf
      self.xff = xff
      self.steps = steps
      self.rows = rows
      self.rrdcs_str()
   
   def rrdcs_str(self):
      return 'RRA:%s:%f:%d:%d' % (self.cf, self.xff, self.steps, self.rows)


class RRDCreator(RRDFileNamer):
   logger = logging.getLogger('RRDCreator')
   log = logger.log
   DST = 'DERIVE'
   min = 0
   def __init__(self, rrd_base_filename, iface_specs, ds_l, rra_specs, step,
         heartbeat, rrd_max):
      self.rrd_base_filename = rrd_base_filename
      self.iface_specs = iface_specs
      self.ds_l = ds_l
      self.rra_specs = rra_specs
      self.step = step
      self.heartbeat = heartbeat
      self.max = rrd_max
   
   def create(self):
      for rrd_filename in self.rrd_fn_iter_allbyifaceandds(self.iface_specs, self.ds_l):
         rfn_abs = os.path.abspath(rrd_filename)
         self.log(20, 'Creating %r.' % (rfn_abs,))
         rdir = os.path.dirname(rrd_filename)
         if not (os.path.exists(rdir)):
            os.makedirs(rdir)
         args = [rrd_filename, '-s', str(int(self.step)),
            'DS:%s:%s:%d:%s:%s' % (self.DS_RAW, self.DST,
            self.heartbeat,self.min,self.max)]
         args.extend([rra.rrdcs_str() for rra in self.rra_specs])
         rrdtool.create(*args)

