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

# Classes for managing rrd db file naming

from constants import *

class RRDFileNamer:
   RRD_FN_FMT = '%s%s_%s_%s/%s.rrd'
   FN_DIR = {
      DIR_IN:'in',
      DIR_OUT:'out'
   }
   FN_CT = {
      CT_BYTES:'bytes',
      CT_PACKETS:'packets'
   }
   DS_RAW = 'data'
   def rrd_fn_get(self, iface, dir_, counter_type, ds):
      return self.RRD_FN_FMT % (self.rrd_base_filename, iface, self.FN_DIR[dir_], self.FN_CT[counter_type], ds)

   def rrd_fn_iter_allbyifaceandds(self, iface_specs, ds_s):
      for iface_spec in iface_specs:
         for dirstring in self.FN_DIR.values():
            for cts in self.FN_CT.values():
               for ds in ds_s:
                  yield self.RRD_FN_FMT % (self.rrd_base_filename, iface_spec, dirstring, cts, ds)