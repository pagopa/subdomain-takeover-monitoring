#!/usr/bin/env python3
import hcl2
import json
import os
import sys

def load_tfvars(file_path):
    with open(file_path, 'r') as f:
        return hcl2.load(f)

def export_variables(data, prefix="TF_VAR_"):
    for key, value in data.items():
        json_val = json.dumps(value)
        env_var = f"{prefix}{key}"
        os.environ[env_var] = json_val
        print(f"Exported {env_var}={json_val}")

if __name__ == "__main__":
    file_path = sys.argv[1] if len(sys.argv) > 1 else "terraform.tfvars"
    try:
        data = load_tfvars(file_path)
        export_variables(data)
    except Exception as e:
        print(f"Error in parsing: {e}")
        sys.exit(1)
