"""SecureSMS - three-block hash-linking demonstration.
Educational model only: not the Bitcoin consensus protocol.
Run: python3 SecureSMS_Blockchain_Demo.py
"""
import copy
import hashlib
import json


def payload(block):
    return {key: block[key] for key in ("index", "transactions", "previous_hash", "nonce")}


def calculate_hash(block):
    encoded = json.dumps(payload(block), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def mine(block, leading_zeros=2):
    target = "0" * leading_zeros
    while True:
        digest = calculate_hash(block)
        if digest.startswith(target):
            block["hash"] = digest
            return block
        block["nonce"] += 1


def new_block(index, tx, previous_hash, difficulty=2):
    block = {"index": index, "transactions": tx, "previous_hash": previous_hash, "nonce": 0}
    return mine(block, difficulty)


def validate(chain, difficulty=2):
    issues = []
    for i, block in enumerate(chain):
        actual = calculate_hash(block)
        if block["hash"] != actual:
            issues.append(f"Block {i+1}: stored hash does not match its contents")
        if not actual.startswith("0" * difficulty):
            issues.append(f"Block {i+1}: current content fails demo proof of work")
        expected_previous = "0" * 64 if i == 0 else chain[i - 1]["hash"]
        if block["previous_hash"] != expected_previous:
            issues.append(f"Block {i+1}: previous_hash is inconsistent")
    return issues


def report(title, chain):
    print("\n" + title)
    print("-" * len(title))
    for b in chain:
        print(f"Block {b['index']}: {b['transactions']} | nonce={b['nonce']}")
        print(f"   previous_hash: {b['previous_hash']}")
        print(f"   stored hash  : {b['hash']}")
        print(f"   actual hash  : {calculate_hash(b)}")
    issues = validate(chain)
    if issues:
        print("VALIDATION: INVALID")
        for issue in issues:
            print(" -", issue)
    else:
        print("VALIDATION: VALID")


def main():
    difficulty = 2  # intentionally easy; no relation to Bitcoin's current difficulty
    chain = [new_block(1, "Alice -> Bob: 10 BTC (example)", "0" * 64, difficulty)]
    chain.append(new_block(2, "Bob -> Carlos: 3 BTC (example)", chain[-1]["hash"], difficulty))
    chain.append(new_block(3, "Carlos -> Diana: 1 BTC (example)", chain[-1]["hash"], difficulty))
    report("1. ORIGINAL CHAIN", chain)

    altered = copy.deepcopy(chain)
    altered[0]["transactions"] = "Alice -> Bob: 100 BTC (example)"
    report("2. TAMPER WITH BLOCK 1 WITHOUT UPDATING ITS HASH", altered)

    altered[0]["nonce"] = 0
    mine(altered[0], difficulty)
    report("3. RE-MINE BLOCK 1 ONLY: BLOCK 2 NOW POINTS TO THE OLD HASH", altered)

    for i in range(1, len(altered)):
        altered[i]["previous_hash"] = altered[i-1]["hash"]
        altered[i]["nonce"] = 0
        mine(altered[i], difficulty)
    report("4. RE-MINE ALL SUCCESSORS: INTERNAL LINKS RESTORED", altered)
    print("\nNote: An internally valid demo chain does not imply acceptance by Bitcoin nodes.")


if __name__ == "__main__":
    main()
