from model import CacheBasedWRModel

if __name__ == "__main__":
    model = CacheBasedWRModel("cb_wr.bin", "main")
    model.run()