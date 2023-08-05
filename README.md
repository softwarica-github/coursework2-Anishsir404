# Antivirious_in_python
## This is a sample antivirious made by anish.
`this antivirious takes three input.`
1. Scan full system.
2. Scan the give directory.
3. Live manitering the given directory.

## What does it do?
The system includes a database with MD5 hashes of known malware. It functions by computing each file's hash and comparing it to the database. When a suspicious file is found, the user is asked if they want to delete it. The system also makes use of a sizable collection of modern and sophisticated YARA rules, sourced from https://github.com/Yara-Rules/rules and numbering over 1000 rules. It checks files for compliance with these rules and alerts the user to any suspicious findings so they can choose whether to delete the file or not. 
Furthermore, the system uses watchdog library functionality for live monitoring, which keeps track of file system events like creations, modifications, and deletions within a given directory. If any suspicious activity is found, the system investigates it using hash and rule checks and gives the user pertinent information. All events are logged into a file in order to keep track of runtime activities. The system makes effective use of a Bloom Filter data structure to find malware hashes. A Bloom Filter is a probabilistic data structure for representing a set of elements that makes use of a bit array and numerous hashing operations.

## How to use it.
```
git clone https://github.com/Anishsir404/Antivirious_in_python.git
```
```
cd Antivirious_in_python
git clone https://github.com/Yara-Rules/rules.git
```
```
pip -i requirement.txt
```
```
python main.py
```