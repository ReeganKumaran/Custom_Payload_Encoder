#!/bin/bash

# Advanced Payload Obfuscation Framework - Interactive Menu
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${CYAN}🎯 Advanced Payload Obfuscation Framework${NC}"
echo -e "${CYAN}===========================================${NC}"
echo ""

while true; do
    echo -e "${YELLOW}Select an option:${NC}"
    echo -e "${GREEN}1)${NC} Process payload from file (shows detailed steps)"
    echo -e "${GREEN}2)${NC} View sample payloads"
    echo -e "${GREEN}3)${NC} Exit"
    echo ""
    echo -ne "${BLUE}Enter your choice [1-3]: ${NC}"
    read choice
    
    case $choice in
        1)
            echo ""
            echo -e "${YELLOW}Select payload source:${NC}"
            echo -e "${GREEN}1)${NC} Choose from sample_payloads/ folder"
            echo -e "${GREEN}2)${NC} Enter custom file path"
            echo ""
            echo -ne "${BLUE}Enter choice [1-2]: ${NC}"
            read source_choice
            
            if [ "$source_choice" = "2" ]; then
                echo ""
                echo -ne "${BLUE}Enter full path to payload file: ${NC}"
                read custom_file
                
                if [ -f "$custom_file" ]; then
                    selected_file="$custom_file"
                    filename=$(basename "$custom_file")
                    echo -e "${CYAN}Selected: $filename${NC}"
                else
                    echo -e "${RED}❌ File not found: $custom_file${NC}"
                    continue
                fi
            else
                echo ""
                echo -e "${YELLOW}📁 Available payload files:${NC}"
                if [ -d "sample_payloads" ]; then
                    files=(sample_payloads/*)
                    if [ ${#files[@]} -eq 0 ] || [ ! -f "${files[0]}" ]; then
                        echo -e "${RED}❌ No payload files found${NC}"
                        continue
                    else
                        echo ""
                        for i in "${!files[@]}"; do
                            filename=$(basename "${files[$i]}")
                            content=$(cat "${files[$i]}" 2>/dev/null | head -1)
                            echo -e "${GREEN}$((i+1)))${NC} $filename - ${CYAN}$content${NC}"
                        done
                        
                        echo ""
                        echo -ne "${BLUE}Select file [1-${#files[@]}]: ${NC}"
                        read file_choice
                        
                        if [[ $file_choice =~ ^[0-9]+$ ]] && [ $file_choice -ge 1 ] && [ $file_choice -le ${#files[@]} ]; then
                            selected_file="${files[$((file_choice-1))]}"
                            filename=$(basename "$selected_file")
                            echo -e "${CYAN}Selected: $filename${NC}"
                        else
                            echo -e "${RED}❌ Invalid selection${NC}"
                            continue
                        fi
                    fi
                else
                    echo -e "${RED}❌ sample_payloads directory not found${NC}"
                    continue
                fi
            fi
            
            echo ""
            # Chain selection
            echo -e "${YELLOW}Select obfuscation chain:${NC}"
            echo -e "${GREEN}1)${NC} Basic (unicode + base64)"
            echo -e "${GREEN}2)${NC} Stealth (unicode + base64 + xor + junk) [DEFAULT]"
            echo -e "${GREEN}3)${NC} Full (OS-specific bypasses included)"
            echo ""
            echo -ne "${BLUE}Enter chain [1-3]: ${NC}"
            read chain_choice
            
            case $chain_choice in
                1) chain="basic" ;;
                3) chain="full" ;;
                *) chain="stealth" ;;
            esac
            
            echo ""
            echo -e "${YELLOW}Select target OS:${NC}"
            echo -e "${GREEN}1)${NC} Windows"
            echo -e "${GREEN}2)${NC} Linux"
            echo -e "${GREEN}3)${NC} Both [DEFAULT]"
            echo ""
            echo -ne "${BLUE}Enter target [1-3]: ${NC}"
            read target_choice
            
            case $target_choice in
                1) target="windows" ;;
                2) target="linux" ;;
                *) target="both" ;;
            esac
            
            echo ""
            echo -e "${YELLOW}Number of variants:${NC}"
            echo -e "${GREEN}1)${NC} 1 variant"
            echo -e "${GREEN}2)${NC} 3 variants [DEFAULT]"
            echo -e "${GREEN}3)${NC} 5 variants"
            echo ""
            echo -ne "${BLUE}Enter choice [1-3]: ${NC}"
            read var_choice
            
            case $var_choice in
                1) variants="1" ;;
                3) variants="5" ;;
                *) variants="3" ;;
            esac
            
            echo ""
            echo -e "${PURPLE}🚀 Processing payload with detailed steps...${NC}"
            echo ""
            
            # Run the framework
            python3 main.py --file "$selected_file" --chain "$chain" --target "$target" --variants "$variants" --verbose
            
            echo ""
            echo -e "${YELLOW}💾 Save encoded payload to file?${NC}"
            echo -e "${GREEN}1)${NC} Yes"
            echo -e "${GREEN}2)${NC} No [DEFAULT]"
            echo ""
            echo -ne "${BLUE}Save? [1-2]: ${NC}"
            read save_choice
            
            if [ "$save_choice" = "1" ]; then
                echo ""
                echo -e "${YELLOW}Select save location:${NC}"
                echo -e "${GREEN}1)${NC} Save in current directory"
                echo -e "${GREEN}2)${NC} Enter custom path"
                echo ""
                echo -ne "${BLUE}Enter choice [1-2]: ${NC}"
                read location_choice
                
                if [ "$location_choice" = "2" ]; then
                    echo ""
                    echo -ne "${BLUE}Enter full path for output file: ${NC}"
                    read save_filename
                    if [ -z "$save_filename" ]; then
                        save_filename="encoded_payload_$(date +%Y%m%d_%H%M%S).txt"
                    fi
                else
                    echo ""
                    echo -ne "${BLUE}Enter filename (default: encoded_payload.txt): ${NC}"
                    read save_filename
                    if [ -z "$save_filename" ]; then
                        save_filename="encoded_payload_$(date +%Y%m%d_%H%M%S).txt"
                    fi
                fi
                
                echo -e "${CYAN}Extracting obfuscated payload...${NC}"
                
                # Extract payload directly without external script
                python3 main.py --file "$selected_file" --chain "$chain" --target "$target" --variants "1" 2>&1 | \
                sed -n '/Ready for deployment:/,$ p' | \
                tail -n +2 > "$save_filename"
                
                if [ -s "$save_filename" ]; then
                    echo -e "${GREEN}✅ Payload saved to: $save_filename${NC}"
                    echo -e "${CYAN}📊 Size: $(wc -c < "$save_filename") bytes${NC}"
                    echo -e "${CYAN}🔍 Preview: $(head -c 100 "$save_filename")...${NC}"
                    echo -e "${GREEN}Success! Payload saved.${NC}"
                else
                    echo -e "${RED}❌ Failed to extract payload${NC}"
                    rm -f "$save_filename"
                fi
            fi
            ;;
        2)
            echo ""
            echo -e "${YELLOW}📋 Sample payloads:${NC}"
            if [ -d "sample_payloads" ]; then
                for file in sample_payloads/*; do
                    if [ -f "$file" ]; then
                        echo -e "${GREEN}$(basename "$file"):${NC} $(cat "$file")"
                    fi
                done
            else
                echo -e "${RED}❌ sample_payloads directory not found${NC}"
            fi
            ;;
        3)
            echo ""
            echo -e "${GREEN}👋 Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Invalid option${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read
    clear
    echo -e "${CYAN}🎯 Advanced Payload Obfuscation Framework${NC}"
    echo -e "${CYAN}===========================================${NC}"
    echo ""
done