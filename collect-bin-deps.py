#!/usr/bin/env python3

# Script to collect binary dependencies (eg shared libraries required by an executable)
#
# Copyright (c) 2020 Frank Richter
#
# This software is provided 'as-is', without any express or implied warranty.
# In no event will the authors be held liable for any damages arising from
# the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
#     1. The origin of this software must not be misrepresented; you must not
#        claim that you wrote the original software. If you use this software
#        in a product, an acknowledgment in the product documentation would be
#        appreciated but is not required.
#
#     2. Altered source versions must be plainly marked as such, and must not
#        be misrepresented as being the original software.
#
#     3. This notice may not be removed or altered from any source distribution.

import argparse
import filecmp
import os
import pefile
import shutil
import sys

# Based on: https://stackoverflow.com/a/20422915
class ActionNoYes(argparse.Action):
  def __init__(self, option_strings, dest, default=None, required=False, help=None):

    if default is None:
      raise ValueError('You must provide a default with Yes/No action')
    opt_long = list(filter(lambda s: s.startswith('--'), option_strings))
    if len(opt_long)!=1:
      raise ValueError('Only single \'--\' argument is allowed with YesNo action')
    opt = opt_long[0]

    opt = opt[2:]
    opts = list(filter(lambda s: not s in opt_long, option_strings)) + ['--' + opt, '--no-' + opt]
    super(ActionNoYes, self).__init__(opts, dest, nargs=0, const=None, 
                                      default=default, required=required, help=help)
  def __call__(self, parser, namespace, values, option_strings=None):
    if option_strings.startswith('--no-'):
      setattr(namespace, self.dest, False)
    else:
      setattr(namespace, self.dest, True)

parser = argparse.ArgumentParser(description='Collect binary dependencies.', fromfile_prefix_chars='@')
parser.add_argument('-t', '--target', action='append', metavar='BINARY', help='target binary to scan', required=True)
parser.add_argument('dependency_dir', metavar='DIR', nargs='*', help='directory to check for dependencies')
parser.add_argument('-o', '--outdir', metavar='OUTPUT-DIR', dest='output_dir', help='override output directory (default: directory of target binary)')
parser.add_argument('--recursive', action=ActionNoYes, default=True, help='whether to scan recursively for depencies (default: yes)')
parser.add_argument('--debug-info', action=ActionNoYes, default=True, help='whether to collect debug info files (default: yes)')
parser.add_argument('-e', '--existing', choices=['skip', 's', 'overwrite', 'o', 'overwrite-different', 'od', 'overwrite-older', 'oo'],
                    default='skip', help='how to handle existing destination files')
parser.add_argument('-l', '--list-only', action='store_true', help='only print list of found dependencies')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')

args = parser.parse_args()

# Helper: print if in verbose mode
def verbose_print(*print_args, **kwargs):
  if args.verbose:
    print(*print_args, file=sys.stderr, **kwargs)

# Helper: extract normalized basename
def norm_basename(path):
  return os.path.normcase(os.path.basename(path))

# Extract names of dependent DLLs from a PE file
def extract_pefile_dependencies(pe_path):
  pe = pefile.PE(pe_path)
  return [os.fsdecode(entry.dll) for entry in pe.DIRECTORY_ENTRY_IMPORT]

# Scan candidate directories, return found paths
def search_dependency(dependency):
  dep_basename = os.path.basename(dependency)
  for dir in args.dependency_dir:
    full_path = os.path.join(dir, dep_basename)
    if os.path.exists(full_path):
      return full_path
  return None


# "Copy" function: print only source path
def _copy_print(src_path, dest_path):
  print(os.path.normpath(src_path))

# Copy function: skip existing destination files
def _copy_skip_existing(src_path, dest_path):
  if os.path.exists(dest_path):
    verbose_print("Skipping existing:", dest_path)
  else:
    verbose_print("Copying:", src_path, "->", dest_path)
    shutil.copy2(full_path, dest_path)

# Copy function: overwrite existing destination files
def _copy_overwrite(src_path, dest_path):
  verbose_print("Copying:", src_path, "->", dest_path)
  shutil.copy2(full_path, dest_path)

# Copy function: overwrite destination files if stat differs from source
def _copy_overwrite_different(src_path, dest_path):
  do_skip = False
  if os.path.exists(dest_path) and filecmp.cmp(src_path, dest_path):
    # filecmp doesn't consider timestamps, but we want to
    src_stat = os.stat(src_path)
    dst_stat = os.stat(dest_path)
    do_skip = dst_stat.st_mtime_ns == src_stat.st_mtime_ns
  if do_skip:
    verbose_print("Skipping identical:", dest_path)
  else:
    verbose_print("Copying:", src_path, "->", dest_path)
    shutil.copy2(full_path, dest_path)

# Copy function: overwrite destination files if stat is older than source
def _copy_overwrite_older(src_path, dest_path):
  if os.path.exists(dest_path):
    src_stat = os.stat(src_path)
    dst_stat = os.stat(dest_path)
    do_skip = dst_stat.st_mtime_ns >= src_stat.st_mtime_ns
  else:
    do_skip = False
  if do_skip:
    verbose_print("Skipping newer:", dest_path)
  else:
    verbose_print("Copying:", src_path, "->", dest_path)
    shutil.copy2(full_path, dest_path)

# Copy a dependency. Takes care of debug files.
def copy_dependency(src, dst, copy_func):
  copy_list = [(src, dst)]

  # Locate possible debug files
  if args.debug_info:
    debug_exts = ['.pdb', '.debug', '.dbg']
    dst_dir = os.path.dirname(dst)
    for test_ext in debug_exts:
      candidates = [os.path.splitext(src)[0] + test_ext, src + test_ext]
      for debug_cand in candidates:
        if os.path.exists(debug_cand):
          copy_list.append((debug_cand, os.path.join(dst_dir, os.path.basename(debug_cand))))

  for src_path, dest_path in copy_list:
    copy_func(src_path, dest_path)

# Choose "copy" function
# Default to printing list of found dependencies
copy_func = _copy_print
if not args.list_only:
  # Copy files to output dir
  if args.existing.casefold() in ['skip', 's']:
    copy_func = _copy_skip_existing
  elif args.existing.casefold() in ['overwrite', 'o']:
    copy_func = _copy_overwrite
  elif args.existing.casefold() in ['overwrite-different', 'od']:
    copy_func = _copy_overwrite_different
  elif args.existing.casefold() in ['overwrite-older', 'oo']:
    copy_func = _copy_overwrite_older
  else:
    print("Invalid value for 'existing':", args.existing, file=sys.stderr)

# dict of (normalized) dependency name to full path
# Shared between targets so we don't have to repeatedly scan if the same
# dependency occurs multiple times.
known_dependencies = {}
for target in args.target:
  # List of binaries to scan. Extend if recursive is enabled
  files_to_scan = [target]
  while len(files_to_scan) > 0:
    to_scan, *files_to_scan = files_to_scan
    # Collect list of dependencies
    verbose_print("Scanning:", to_scan)
    for dep in extract_pefile_dependencies(to_scan):
      norm_name = norm_basename(dep)
      if norm_name in known_dependencies:
        # Already searched for, no need to check again
        continue
      dep_fn = search_dependency(dep)
      # Store result in any case, to mark we scanned for the file
      known_dependencies[norm_name] = dep_fn
      if dep_fn:
        verbose_print(" Found dependency:", dep_fn)
        if args.recursive:
          files_to_scan.append(dep_fn)
      else:
        verbose_print(" Not found:", norm_name)

  output_dir = os.path.normpath(args.output_dir if args.output_dir else os.path.dirname(target))
  for norm_base, full_path in known_dependencies.items():
    if not full_path: continue  # dependency we haven't found
    dest_path = os.path.join(output_dir, os.path.basename(full_path))
    copy_dependency(full_path, dest_path, copy_func)
