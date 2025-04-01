import os

# compile contracts will different range
for i in range(1, 33):
    f_r = open(
        "../../../circuits-noir/src/main.nr",
        "r",
    )
    f_text = f_r.read()
    last_index = i - 1
    print(f"repace {last_index} to {i}")
    f_text = f_text.replace(
        f"pub global MAX_DEPTH: u32 = {last_index};",
        f"pub global MAX_DEPTH: u32 = {i};",
        1,
    )
    f_r.close()
    f_w = open(
        "../../../circuits-noir/src/main.nr",
        "w",
    )
    f_w.write(f_text)
    f_w.close()
    s = f"cd ../../../circuits-noir; nargo compile; bb write_vk_ultra_keccak_honk -b ./target/circuit.json; bb contract_ultra_honk -o ./contracts/contract-{i}.sol"
    os.system(s)
