#!/usr/bin/env python3
import os
import glob

def main():
    print("Testing directory access...")
    
    # Check if gitleaked directory exists
    if not os.path.exists('gitleaked'):
        print("Error: 'gitleaked' directory not found!")
        return
    
    # Try to find some report files
    pattern = os.path.join('gitleaked', '**', '*_gitleaks.md')
    print(f"Searching for files matching: {pattern}")
    
    report_files = glob.glob(pattern, recursive=True)
    
    if not report_files:
        print("No gitleaks report files found!")
        return
    
    print(f"Found {len(report_files)} report files. First few:")
    for f in report_files[:5]:
        print(f"- {f}")
    
    # Try to read one file
    if report_files:
        try:
            with open(report_files[0], 'r', encoding='utf-8') as f:
                first_few_lines = [next(f) for _ in range(5)]
            print("\nFirst few lines of the first report:")
            print(''.join(first_few_lines))
        except Exception as e:
            print(f"Error reading file: {e}")

if __name__ == "__main__":
    main()
