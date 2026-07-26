import requests
import yaml

def fetch_atomic_test(ttp_id, target_os="windows", test_guid=None, test_index=None):
    """Fetches tests, filters OS, and resolves input variables."""
    print(f"📥 Fetching execution instructions for {ttp_id} targeting {target_os} (GUID: {test_guid or 'First Available'}, Index: {test_index if test_index is not None else 'N/A'})...")

    url = f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{ttp_id}/{ttp_id}.yaml"
    response = requests.get(url)

    if response.status_code == 200:
        try:
            atomic_data = yaml.safe_load(response.text)
            tests = atomic_data.get('atomic_tests', [])

            # 1. If GUID is provided, find that exact test and verify OS compatibility
            target_test = None
            if test_guid:
                for t in tests:
                    if t.get('auto_generated_guid') == test_guid:
                        platforms = [p.lower() for p in t.get('supported_platforms', [])]
                        if target_os.lower() in platforms or 'all' in platforms:
                            target_test = t
                        else:
                            print(f"⚠️ GUID {test_guid} found but not compatible with {target_os}. Falling back.")
                        break
            
            # 2. If index is provided, pick that specific test if it exists
            if not target_test and test_index is not None:
                if 0 <= test_index < len(tests):
                    target_test = tests[test_index]
                    print(f"✅ Using test at index {test_index}: {target_test.get('name')}")
                else:
                    print(f"⚠️ Test index {test_index} out of range for {ttp_id}. Falling back.")

            # 3. If no GUID/index, GUID not found, or incompatible, filter by OS and pick the first
            if not target_test:
                valid_tests = []
                for test in tests:
                    platforms = [p.lower() for p in test.get('supported_platforms', [])]
                    if target_os.lower() in platforms or 'all' in platforms:
                        valid_tests.append(test)

                if not valid_tests:
                    print(f"⚠️ No tests found for {ttp_id} that run on {target_os}.")
                    return None
                
                target_test = valid_tests[0]
            
            # --- NEW: CALCULATE USER CONTEXT ---
            elevation_required = target_test.get('executor', {}).get('elevation_required', False)
            platforms = [p.lower() for p in target_test.get('supported_platforms', [])]
            user_context = "Standard user"
            if elevation_required:
                if any("windows" in p for p in platforms):
                    user_context = "Admin user"
                elif any(p in ["linux", "macos", "unix", "solaris", "aix"] for p in platforms):
                    user_context = "root User"
                else:
                    user_context = "Privileged user"
            target_test['user_context'] = user_context

            command = target_test['executor'].get('command', '')
            cleanup = target_test['executor'].get('cleanup_command', None)

            # --- NEW: RESOLVE VARIABLES ---
            # Replace #{variable} with the default values provided in the YAML
            input_args = target_test.get('input_arguments', {})
            for arg_name, arg_details in input_args.items():
                default_val = arg_details.get('default', '')
                placeholder = f"#{{{arg_name}}}"
                
                command = command.replace(placeholder, str(default_val))
                if cleanup:
                    cleanup = cleanup.replace(placeholder, str(default_val))

            # Put the resolved strings back into the object
            target_test['executor']['command'] = command
            if cleanup:
                target_test['executor']['cleanup_command'] = cleanup

            return {
                "test": target_test,
                "dependencies": target_test.get('dependencies', [])
            }

        except yaml.YAMLError as e:
            print(f"❌ YAML Error: {e}")
    return None