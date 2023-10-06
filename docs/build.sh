#!/bin/bash
#
# Preprocesses docs and runs Sphinx (apidoc and build) to build the HTML docs.
#
# Requires:
#  brew install pandoc
#  pip install sphinx  (in virtualenv)
set -e

absfile=`readlink -f $0`
cd `dirname $absfile`

# sphinx-apidoc -f -o source ../ ../tests

rm -f index.rst
cat > index.rst <<EOF
Bridgy Fed developer documentation
----------------------------------

EOF

tail -n +4 ../README.md \
  | pandoc --from=markdown --to=rst \
  | sed -E 's/```/`/; s/`` </ </' \
  >> index.rst

source ../local/bin/activate

# Run sphinx in the virtualenv's python interpreter so it can import packages
# installed in the virtualenv.
#
# If sphinx crashes with eg:
#   exception: '<' not supported between instances of 'dict' and 'dict'
# ...try running with -E to clear its cache.
python3 `which sphinx-build` -b html . _build/html
