#   Copyright 2026 UCP Authors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


"""MkDocs hooks for UCP documentation.

This module contains functions that are executed during the MkDocs build
process.
Currently, it includes a hook to copy specs files into the site directory
after the build is complete.
This makes the specs JSON files available in the website and programmatically
accessible.
"""

import json
import logging
import os
import shutil

log = logging.getLogger('mkdocs')


def on_post_build(config):
  """Moves files from the spec/ directory to the site directory based on their $id.

  Args:
      config: The mkdocs config object.
  """

  # Base path for the source directories
  base_src_path = os.path.join(os.getcwd(), 'spec')

  # Check if the parent 'spec' folder exists first
  if not os.path.exists(base_src_path):
    log.warning('Spec source directory not found: %s', base_src_path)
    return

  # Iterate over everything inside 'spec'
  for root, _, files in os.walk(base_src_path):
    for filename in files:
      src_file = os.path.join(root, filename)

      # Default to relative path (copy as-is)
      rel_path = os.path.relpath(src_file, base_src_path)

      try:
        with open(src_file, 'r') as f:
          data = json.load(f)
          file_id = data.get('$id')

          # If the file has a valid $id, use it to generate a destination path.
          prefix = 'https://ucp.dev'
          if file_id and file_id.startswith(prefix):
            rel_path = file_id[len(prefix) :].lstrip('/')

      except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        log.error(
            'Failed to parse or read JSON file %s (copying as-is): %s',
            src_file,
            e,
        )

      dest_file = os.path.join(config['site_dir'], rel_path)
      dest_dir = os.path.dirname(dest_file)

      os.makedirs(dest_dir, exist_ok=True)
      shutil.copy2(src_file, dest_file)
      log.info('Copied %s to %s', src_file, dest_file)
