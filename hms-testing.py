import hashlib
import time
import random
import sys
import logging


# Blockchain Implementation
class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # Threat details
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = (
            f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.nonce}"
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        # Simple Proof-of-Work algorithm
        required_prefix = "0" * difficulty
        while not self.hash.startswith(required_prefix):
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty  # Adjust difficulty for mining

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        # data.pop('flag')
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=self.get_latest_block().hash,
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self):
        # Verify the integrity of the blockchain
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != prev.hash:
                return False
        return True

    def display_chain(self):
        for block in self.chain:
            
            print(f"Block {block.index}:")
            print(f"  Timestamp      : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}")
            if type(block.data) == dict:
                # block.data.pop('flag')
                print(f"  Data           : {block.data}")
            else:
                print(f"  Data           : {block.data}")
            print(f"  Hash           : {block.hash}")
            print(f"  Previous Hash  : {block.previous_hash}\n")


# Threat Detection Functions
def detect_unauthorized_access(user, password, access_logs):
    # Simulate checking user credentials against access logs
    # user, password = user_credentials
    if user not in access_logs or access_logs[user] != password:
        return {
            "flag": 1,
            "type": "Unauthorized Access",
            "user": user,
            "timestamp": time.time(),
            "details": "Failed login attempt detected.",
        }
    return {
        "flag": 0,
        "type": "User Logged In",
        "user": user.capitalize(),
        "timestamp": time.time(),
        "details": "Employee Logged into the network",
    }

def detect_sql_injection(input_query):
    # Simple pattern check for SQL injection
    sql_injection_patterns = ["--", ";", "' OR '1'='1", "DROP TABLE", "SELECT * FROM"]
    for pattern in sql_injection_patterns:
        if pattern.lower() in input_query.lower():
            return {
                "flag": 1,
                "type": "SQL Injection Attempt",
                "query": input_query,
                "timestamp": time.time(),
                "details": "SQL injection pattern detected in input.",
            }
    return None

def detect_ransomware_activity(file_system_changes):
    # Simulate detecting rapid file encryption
    if file_system_changes.get("encrypted_files", 0) > 100:
        threat = {
            "flag": 1,
            "type": "Ransomware Activity",
            "timestamp": time.time(),
            "details": f"{file_system_changes['encrypted_files']} files encrypted in short time.",
        }
        return threat
    return None

def detect_all_threat(name, pwd):
    # Simulated access logs
    access_logs = {"doctor": "doc123", "nurse": "nurse123", "admin": "admin123"}
    
    activity = detect_sql_injection(name)
    if activity is None:
        activity = detect_sql_injection(pwd)
        if activity is None:
            activity = detect_unauthorized_access(name, pwd, access_logs)
    return activity

# Threat Monitoring System
class ThreatMonitoringSystem:
    def __init__(self):
        self.blockchain = Blockchain()
        self.threat_log = []

    def log_threat(self, threat):
        sanitized_threat = {k: v for k, v in threat.items() if k != 'flag'}
        self.threat_log.append(threat)
        self.blockchain.add_block(sanitized_threat)
    
    def log_activity(self, activity):
        sanitized_threat = {k: v for k, v in activity.items() if k != 'flag'}
        self.blockchain.add_block(sanitized_threat)

    def display_threats(self):
        if self.threat_log:
            print("\n=== Detected Threats ===")
            for threat in self.threat_log:
                print(f"Type       : {threat['type']}")
                print(f"Timestamp  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(threat['timestamp']))}")
                print(f"Details    : {threat['details']}\n")
        else:
            print("\n=== No Any Threats Detected ===")
            print()



def main():
    # Initialize monitoring system
    monitoring_system = ThreatMonitoringSystem()

    n = random.randint(1, 50)
    # print(n)
    print()
    print()
    # ------------------------- Simulate user login attempts
    print()
    print('=== Login Credentials ===')
    user = input("Enter you username: ")
    pwd = input("Enter you password: ")
    trial = 1

    # function for testing all cases
    threat = detect_all_threat(user, pwd)
    if threat['flag'] == 0:
        monitoring_system.log_activity(threat)
        
        # ------------------------- Simulate file system changes
        
        if n % 2 == 0:
            file_system_changes = {"encrypted_files": random.randint(50, 150)}
            threat = detect_ransomware_activity(file_system_changes)
            if threat:
                monitoring_system.log_threat(threat)
    else:
        monitoring_system.log_threat(threat)
        while threat['flag'] == 1 and trial < 3:
            print('--------------------------------')
            print('|    ===  Login Failed  ===    |')
            print('--------------------------------')
            print()
            print()
            # ------------------------- Simulate user login attempts due to login failed
            print('=== Login Credentials ===')
            user = input("Enter you username: ")
            pwd = input("Enter you password: ")
            threat = detect_all_threat(user, pwd)
            if threat['flag'] == 0:
                monitoring_system.log_activity(threat)
            elif threat['flag'] == 1:
                monitoring_system.log_threat(threat)
            trial += 1


    if trial >= 3 and threat['flag'] == 1:
        print()
        print('=== Login is Blocked as of now for you as you have tried all 3 attempts ===')
    else:
        # Display detected threats
        monitoring_system.display_threats()

        # Display blockchain
        print("=== Blockchain Ledger ===")
        monitoring_system.blockchain.display_chain()

    # Verify blockchain integrity
    is_valid = monitoring_system.blockchain.is_chain_valid()
    print(f"Blockchain valid: {is_valid}")

if __name__ == "__main__":
    main()
