#!/bin/bash

# test.sh - A script to test the server and client programs thoroughly

# Function to compare expected and actual outputs
compare_output() {
    test_name="$1"
    expected="$2"
    actual="$3"

    if [ "$expected" == "$actual" ]; then
        echo "[PASS] $test_name"
    else
        echo "[FAIL] $test_name"
        echo "Expected Output:"
        echo "$expected"
        echo "Actual Output:"
        echo "$actual"
    fi
}

# Clean up any previous test outputs
rm -rf test_output
mkdir test_output

echo "Starting tests..."

########################################
# Test 1: Interactive Mode Testing
########################################

echo "Running Test 1: Interactive Mode Testing"

# Create test_commands.txt with various commands to test server functionality
cat > test_commands.txt <<EOF
A 1.1.1.1 50
A 256.256.256.256 50
A 1.1.1.1-2.2.2.2 50-40
C 1.1.1.1 50
C 2.2.2.2 50
C 1.1.1.1 50
C 1.1.1.1 50
C invalid_ip 50
D 1.1.1.1 50
D 3.3.3.3 100
D invalid_rule
L
R
InvalidCommand
EOF

# Expected output for the above commands
cat > expected_output.txt <<EOF
Rule added
Invalid rule
Invalid rule
Connection accepted
Connection rejected
Connection accepted
Connection accepted
Illegal IP address or port specified
Rule deleted
Rule not found
Rule invalid
No rules
A 1.1.1.1 50
A 256.256.256.256 50
A 1.1.1.1-2.2.2.2 50-40
C 1.1.1.1 50
C 2.2.2.2 50
C 1.1.1.1 50
C 1.1.1.1 50
C invalid_ip 50
D 1.1.1.1 50
D 3.3.3.3 100
D invalid_rule
L
R
InvalidCommand
Illegal request
EOF

# Run the server in interactive mode with the test commands
timeout 5 ./server -i < test_commands.txt > test_output/interactive_output_raw.txt 2>&1

# Process the server output to remove prompts and empty lines
grep -v -e '^running interactive' -e '^Enter a command: ' test_output/interactive_output_raw.txt | sed '/^$/d' > test_output/interactive_output.txt

# Read the actual and expected outputs
actual_output=$(cat test_output/interactive_output.txt)
expected_output=$(cat expected_output.txt)

# Compare the outputs
compare_output "Interactive Mode Test" "$expected_output" "$actual_output"

# Clean up temporary files
rm test_commands.txt expected_output.txt test_output/interactive_output_raw.txt

########################################
# Test 2: Client and Server Interaction Testing
########################################

echo "Running Test 2: Client and Server Interaction Testing"

# Start the server in port mode in the background
./server 2200 > test_output/server_output.txt 2>&1 &
server_pid=$!

# Give the server time to start
sleep 1

# Function to test client commands
test_client_command() {
    test_name="$1"
    command="$2"
    expected="$3"

    # Run the client command and capture the output
    actual=$(./client localhost 2200 $command)

    if [ "$actual" == "$expected" ]; then
        echo "[PASS] $test_name"
    else
        echo "[FAIL] $test_name"
        echo "Command: ./client localhost 2200 $command"
        echo "Expected Output:"
        echo "$expected"
        echo "Actual Output:"
        echo "$actual"
    fi
}

# Test cases for the client interacting with the server

# Test adding a valid rule
test_client_command "Client Add Valid Rule" "A 4.4.4.4 80" "Rule added"

# Test adding an invalid rule
test_client_command "Client Add Invalid Rule" "A 256.256.256.256 80" "Invalid rule"

# Test checking an allowed connection
test_client_command "Client Check Allowed Connection" "C 4.4.4.4 80" "Connection accepted"

# Test checking a rejected connection
test_client_command "Client Check Rejected Connection" "C 5.5.5.5 80" "Connection rejected"

# Test checking with invalid IP
test_client_command "Client Check Invalid IP" "C invalid_ip 80" "Illegal IP address or port specified"

# Test deleting a valid rule
test_client_command "Client Delete Valid Rule" "D 4.4.4.4 80" "Rule deleted"

# Test deleting a non-existing rule
test_client_command "Client Delete Non-existing Rule" "D 4.4.4.4 80" "Rule not found"

# Test deleting an invalid rule
test_client_command "Client Delete Invalid Rule" "D invalid_rule" "Rule invalid"

# Test listing rules (should be empty now)
expected_output="No rules"
actual_output=$(./client localhost 2200 L)
if [ "$actual_output" == "$expected_output" ]; then
    echo "[PASS] Client List Rules"
else
    echo "[FAIL] Client List Rules"
    echo "Expected Output:"
    echo "$expected_output"
    echo "Actual Output:"
    echo "$actual_output"
fi

# Test listing requests
expected_output=$(cat <<EOF
A 4.4.4.4 80
A 256.256.256.256 80
C 4.4.4.4 80
C 5.5.5.5 80
C invalid_ip 80
D 4.4.4.4 80
D 4.4.4.4 80
D invalid_rule
L
R
EOF
)
actual_output=$(./client localhost 2200 R)
if [ "$actual_output" == "$expected_output" ]; then
    echo "[PASS] Client List Requests"
else
    echo "[FAIL] Client List Requests"
    echo "Expected Output:"
    echo "$expected_output"
    echo "Actual Output:"
    echo "$actual_output"
fi

# Test invalid command
test_client_command "Client Invalid Command" "InvalidCommand" "Illegal request"

# Test client called incorrectly (missing command argument)
./client localhost 2200 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Client Incorrect Usage"
else
    echo "[FAIL] Client Incorrect Usage"
    echo "Expected an error message when client is called incorrectly."
fi

# Clean up: Kill the server process
kill $server_pid

wait $server_pid 2>/dev/null

echo "Tests completed."