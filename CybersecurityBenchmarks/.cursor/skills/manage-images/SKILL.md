---
name: manage-images
description: Manage Docker images in the ARVO benchmark Artifact Registry. Use when the user wants to list, inspect, delete, or clean up Docker images, check image tags, find images for specific cases, or remove built images for an experiment. Also use when the user mentions image cleanup, registry, or built images.
---

# Manage ARVO Docker Images

ARVO benchmark workflows build Docker images per case and push them to Google Artifact Registry. Images are shared across experiments via build-version tags.

## Image Types

| Suffix         | Description                               | Base Image                                                            | Built By                        |
| -------------- | ----------------------------------------- | --------------------------------------------------------------------- | ------------------------------- |
| `-vul`         | Vulnerable build with modified libfuzzer  | `arvo-{case}-closest-vul:latest` (or upstream `n132/arvo:{case}-vul`) | `build-vul` workflow step       |
| `-fix`         | Fixed build with CASR, DD, libfuzzer      | `n132/arvo:{case}-fix`                                                | `build-fix` workflow step       |
| `-closest-vul` | Upstream base for closest-vul experiments | External                                                              | Pre-built, not workflow-managed |

## Naming Convention

```
{registry}/arvo-{case_id}-{suffix}:{build_version}
```

Example: `us-central1-docker.pkg.dev/fellows-safety-research/arvo/arvo-11429-vul:cd72f555`

## Configuration

Registry and bucket are read from `benchmark/gcp/.gke-config.json`:

```bash
REGISTRY=$(python3 -c "import json; print(json.load(open('benchmark/gcp/.gke-config.json'))['artifact_registry'])")
BUCKET=$(python3 -c "import json; print(json.load(open('benchmark/gcp/.gke-config.json'))['bucket_name'])")
```

Build version is either a literal string from the config (e.g. `closest-vul-msan-fixed`) or an auto-computed content hash (e.g. `cd72f555`). Check the experiment config's `build_version` field -- if `"auto"`, the CLI computes a hash at submit time.

## Commands

### List all images for a case

```bash
gcloud artifacts docker images list $REGISTRY/arvo-{case_id}-vul --include-tags --format="value(IMAGE,TAGS)"
gcloud artifacts docker images list $REGISTRY/arvo-{case_id}-fix --include-tags --format="value(IMAGE,TAGS)"
```

### List all images in registry (slow, ~25s)

```bash
gcloud artifacts docker images list $REGISTRY --include-tags --format="value(IMAGE,TAGS)"
```

### Count images with a specific build version tag

```bash
gcloud artifacts docker images list $REGISTRY --include-tags --format="value(IMAGE,TAGS)" | grep "{build_version}" | wc -l
```

### Check if an image exists for a case + build version

```bash
gcloud artifacts docker images list $REGISTRY/arvo-{case_id}-{suffix} --include-tags --format="value(TAGS)" | grep -q "{build_version}" && echo "exists" || echo "missing"
```

### Delete a single image by tag

```bash
gcloud artifacts docker images delete $REGISTRY/arvo-{case_id}-{suffix}:{build_version} --delete-tags --quiet
```

### Delete all images (all tags/versions) for a case

```bash
gcloud artifacts docker packages delete $REGISTRY/arvo-{case_id}-vul --quiet
gcloud artifacts docker packages delete $REGISTRY/arvo-{case_id}-fix --quiet
```

## Bulk Operations

### Delete -vul and -fix images for all cases in a config

Generate the image list from a config file, then delete in parallel:

```bash
python3 -c "
import json
with open('{config_file}') as f:
    data = json.load(f)
for c in data['cases']:
    for suffix in ['vul', 'fix']:
        print(f'$REGISTRY/arvo-{c}-{suffix}:{build_version}')
" > /tmp/images_to_delete.txt

cat /tmp/images_to_delete.txt | xargs -P 10 -I{} gcloud artifacts docker images delete {} --delete-tags --quiet
```

Use `-P 10` for 10 parallel deletes. Some may fail (exit code 1) if images don't exist for all cases -- this is expected.

### Delete -vul and -fix images for a specific experiment

Extract case IDs from GCS results, then delete:

```bash
gsutil ls "gs://$BUCKET/results/{experiment_id}/" | sed 's|.*/results/[^/]*/||;s|/$||' | sort -n > /tmp/cases.txt

while read case_id; do
  for suffix in vul fix; do
    echo "$REGISTRY/arvo-${case_id}-${suffix}:{build_version}"
  done
done < /tmp/cases.txt > /tmp/images_to_delete.txt

cat /tmp/images_to_delete.txt | xargs -P 10 -I{} gcloud artifacts docker images delete {} --delete-tags --quiet
```

### Full experiment cleanup (results + images)

1. Delete GCS results:

```bash
gsutil -m rm -r "gs://$BUCKET/results/{experiment_id}/"
```

2. Delete Docker images (see bulk delete above)

## Discovering Build Version

If the build version isn't obvious from the config:

```bash
# Check what tags exist for a known case in the experiment
gcloud artifacts docker images list $REGISTRY/arvo-{case_id}-vul --include-tags --format="value(TAGS)"
```

If the config uses `"build_version": "auto"`, the actual tag is a content hash computed by `compute_image_build_version()` in `benchmark/gcp/cli/hashing.py`. Inspect existing image tags to find it.

## Safety Notes

- Images are **shared across experiments**. Deleting `arvo-{case}-vul:{version}` affects ALL experiments using that case + build version.
- The `-closest-vul:latest` images are upstream base images -- avoid deleting unless intentional.
- Always list before bulk deleting. Use `wc -l` to verify scope.
- Bulk deletes with `xargs -P` may report exit code 1 if some images are missing -- check output for actual errors vs expected "not found" messages.
