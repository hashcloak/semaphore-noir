f = open(
    "/Users/liaoyuchen/Developer/semaphore-noir/packages/circuits/target/contract.sol",
    "r",
)
o = open("output.txt", "a")

for x in f:
    if x.strip() == "return vk;":
        break
    if x.strip().startswith("0x"):
        o.write("hex" + '"' + x.strip()[2:] + '"' + "\n")
