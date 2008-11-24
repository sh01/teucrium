#!/usr/bin/env python
#Copyright 2008 Sebastian Hagen
# This file is part of teucrium.

# teucrium is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 
# as published by the Free Software Foundation
#
# teucrium is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from distutils.core import setup
from distutils.command.install_scripts import install_scripts as _install_scripts
from distutils.util import byte_compile


class install_scripts(_install_scripts):
   def run(self, *args, **kwargs):
      # __ugly__
      tdir = os.path.join(os.path.split(self.install_dir.rstrip('/'))[0], 'sbin/')
      if not (os.path.exists(tdir)):
         os.makedirs(tdir)
      fn = os.path.join(tdir, 'teucrium')
      fn_src = 'src/teucrium/main.py'
      byte_compile((fn_src,))
      self.copy_file(fn_src + 'c', fn)
      os.system('chmod g+x,o-x %r' % (fn,))

setup(name='teucrium',
   version='0.3',
   description='teucrium: using linux netfilter and rrdtool to graph traffic',
   author='Sebastian Hagen',
   author_email='sebastian_hagen@memespace.net',
   url='http://git.memespace.net/git/teucrium.git',
   packages=('teucrium',),
   package_dir={'teucrium':'src/teucrium'},
   scripts=('src/teucrium/main.py',),
   data_files=(
      ('/etc/teucrium/', ('examples/teucrium.conf.example',)),
   ),
   cmdclass={'install_scripts': install_scripts}
)

