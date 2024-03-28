#! /usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
rm -rf $(dirname $0)/../../ats-manifest
all_args="$@"
if [ "$all_args" == "package" ]; then
    ./build_manifest.sh
fi

cd $(dirname $0)
exec "${GO:-go}" run *.go "$@"
