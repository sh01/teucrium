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
import optparse
import sys

from gonium.fd_management import EventDispatcherSelect as ED
from gonium import pid_filing, daemon_init

try:
   from teucrium.config_structures import TeucriumConfig
except ImportError:
   from config_structures import TeucriumConfig

logger = logging.getLogger()
log = logger.log

def op_get():
   op = optparse.OptionParser(usage="teucrium [options] <action>\nactions: " + ' '.join(actions.keys()))
   op.add_option('-c', '--config', dest='cfn', help='config file to read', metavar='FILE')
   
   og_daemon = optparse.OptionGroup(op, 'daemon options')
   og_daemon.add_option('-p', '--pid-file', dest='pfn', help='pid file to use', metavar='FILE', default='teucrium.pid')
   og_daemon.add_option('--debug-mode', dest='ddebug', help="don't fork, redirect output or suppress log messages", action='store_true', default=False)
   op.add_option_group(og_daemon)
   
   og_daemon_dep = optparse.OptionGroup(op, 'daemon options (DEPRECATED)')
   og_daemon_dep.add_option('--force-uid0', dest='tolerateuid0', help="don't refuse to run as uid 0", action='store_true', default=False)
   op.add_option_group(og_daemon_dep)
   
   return op

def error_exit(msg, rcode=255):
   print('FATAL: ' + msg)
   sys.exit(rcode)

def act_rrdcreate(options, xtrs, ls):
   for xtr in xtrs:
      rrdc = xtr.rrdc_build()
      rrdc.create()
   sys.exit(0)

def act_xtsetup(options, xtrs, ls):
  for xtr in xtrs:
     xtr.xt_call()

def act_daemon(options, xtrs, ls):
   # Override the following test at your own peril. It's safer to run teucrium with
   # only CAP_NET_ADMIN. See capabilities(7), setcap(8) and teucrium's README for
   # details.
   if ((os.getuid() == 0) and not options.tolerateuid0):
      raise StandardError("It is not advised to run this program as root.")
   rrdtcs = []
   ed = ED()
   for xtr in xtrs:
      # Check if the interface works and we have the needed permissions
      try:
         xtr.xt_cls().get_info(xtr.tablename)
      except ValueError:
         error_exit('Attempting to access NF table %r using %r failed.\nCheck if the table is present and you have CAP_NET_ADMIN.' % (xtr.tablename, xtr.xt_cls.__name__))
      rrdtcs.append(xtr.rrdtc_build(ed))
   
   if not (options.ddebug):
      # Somewhat ugly, but can't be avoided.
      ls()
      pid_filing.release_pid_file(pid_filing.file_pid())
      daemon_init.daemon_init()
      pid_filing.file_pid()
   ed.event_loop()
   
def act_graph(options, xtrs, ls):
   for xtr in xtrs:
      rrdg = xtr.rrdg_build()
      rrdg.data_graph()

actions = {
   'rrdcreate':act_rrdcreate,
   'daemon':act_daemon,
   'xtsetup':act_xtsetup,
   'graph':act_graph
}

def main():
   logger.setLevel(0)
   formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
   handler_stderr = logging.StreamHandler()
   handler_stderr.setLevel(20)
   handler_stderr.setFormatter(formatter)
   logger.addHandler(handler_stderr)
   
   def logger_shutdown():
      logger.removeHandler(handler_stderr)
   
   tc = TeucriumConfig()
   op = op_get()
   (options, args) = op.parse_args()
   if (len(args) < 1):
      error_exit("Missing <action> argument.")
   action = args[0]
   try:
      act_func = actions[action]
   except KeyError:
      error_exit('Invalid action %r.' % (action,))
   
   if not (options.cfn is None):
      cfn = os.path.abspath(options.cfn)
      try:
         os.chdir(os.path.dirname(cfn))
         tc.file_read(cfn)
      except OSError:
         error_exit('Unable to read config file %r.' % (fcn,))
   else:
      tc.config_read()
   
   act_func(options, tc.xtrs, logger_shutdown)

if (__name__ == '__main__'):
   main()
