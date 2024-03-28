#! /usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
manifest_dir=`realpath $(dirname $0)/../../`
cd $manifest_dir
rm -rf ats-manifest
git_status="$(git status)"
echo "build command:  $@" >> ats-manifest
echo "ats branch:     " $(git rev-parse --abbrev-ref HEAD) >> ats-manifest
echo "ats commit:     " $(git rev-parse --verify HEAD) >> ats-manifest
echo "ats user:       " $(git config --get user.email) >> ats-manifest

echo "ats timestamp:  " $(date -Is) >> ats-manifest
echo >> ats-manifest
pushd ../cloudn > /dev/null
echo "cloudn branch:  " $(git rev-parse --abbrev-ref HEAD) >> $manifest_dir/ats-manifest
echo "cloudn commit:  " $(git rev-parse --verify HEAD) >> $manifest_dir/ats-manifest
echo "cloudn user:    " $(git config --get user.email) >> $manifest_dir/ats-manifest
popd > /dev/null


echo >> ats-manifest
echo >> ats-manifest
echo =================================================================== >> ats-manifest
printf "%s" "$git_status" >> ats-manifest