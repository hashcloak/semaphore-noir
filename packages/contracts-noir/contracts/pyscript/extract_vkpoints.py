# a script to extract vk from solidity contracts

o = open("output.txt", "a")

for i in range(1, 33):
    # a path to a folder contains all the contracts
    contract = f"../../../circuits-noir/contracts/contract-{i}.sol"
    f = open(contract, "r")
    print(i)
    for x in f:
        if x.strip() == "return vk;":
            break
        if x.strip().startswith("0x"):
            o.write("hex" + '"' + x.strip()[2:] + '"' + "\n")
    f.close()
