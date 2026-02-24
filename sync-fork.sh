#!/bin/bash
# Sync the fork with the upstream repository

# Set the upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/ORIGINAL_REPOSITORY.git

# Fetch the latest changes from upstream
git fetch upstream

# Merge the changes into the local default branch
git checkout main

git merge upstream/main

# Push the changes to the fork
git push origin main

# End of script