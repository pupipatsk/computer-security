def count_freq(txt: str):
    dct = {}
    for ch in txt:
        if ch in dct:
            dct[ch] += 1
        else:
            dct[ch] = 1
    return dct


cipher = "PRCSOFQX FP QDR AFOPQ CZSPR LA JFPALOQSKR. QDFP FP ZK LIU BROJZK MOLTROE."
frq_dict = count_freq(cipher)

for k, v in sorted(frq_dict.items(), key=lambda x: x[1], reverse=True):
    print(k, v)
