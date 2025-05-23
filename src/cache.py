from unicorn import Uc
import binascii

class L1DCache:
    """
    A simple L1D cache model with LRU replacement policy
    """
    def __init__(self, amt_sets=64, amt_ways=8, line_size=64, debug=False):
        """
        Args:
            sets: Number of cache sets (default: 64 for a typical L1D cache)
            ways: Number of ways per set (default: 8-way associative)
            line_size: Size of each cache line in bytes (default: 64 bytes)
        """
        self.amt_sets = amt_sets
        self.amt_ways = amt_ways
        self.line_size = line_size
        self.debug = debug
        
        # Initialize cache structure as a dictionary of sets
        # Each set is a list of (tag, data) tuples representing the ways
        self.cache = {i: [] for i in range(amt_sets)}
    
    def get_set_index(self, address) -> int:
        return (address // self.line_size) % self.amt_sets
    
    def get_tag(self, address) -> int:
        return address // (self.line_size * self.amt_sets)
    
    def is_cached(self, address) -> bool:
        set_index = self.get_set_index(address)
        tag = self.get_tag(address)
        cache_set = self.cache[set_index]
        
        for existing_tag, _ in cache_set:
            if existing_tag == tag:
                if self.debug:
                    print(f"Present in cache: 0x{address:x}")
                return True
        
        if self.debug:
            print(f"Not present in cache: 0x{address:x}")
        return False

    def read(self, address, mu: Uc) -> int:
        if self.debug:
            print(f"Reading from cache: 0x{address:x}")

        set_idx = self.get_set_index(address)
        tag = self.get_tag(address)
        cache_set = self.cache[set_idx]

        for i, (existing_tag, data) in enumerate(cache_set):
            if existing_tag == tag:
                # Cache hit, move to start (MRU position)
                cache_set.insert(0, cache_set.pop(i))
                return data
        
        # Cache miss - read from memory and update cache
        value = mu.mem_read(address, self.line_size)
        self.write(address, value)
        return value
    
    def write(self, address, value):
        set_idx = self.get_set_index(address)
        tag = self.get_tag(address)
        cache_set = self.cache[set_idx]

        for i, (existing_tag, data) in enumerate(cache_set):
            if existing_tag == tag:
                # Cache hit, remove old value and insert new at start (MRU position)
                cache_set.pop(i)
                cache_set.insert(0, (tag, value))
                if self.debug:
                    print(f"Writing to cache: 0x{address:x}, value = {value} (replaced old value)")

                return

        # Cache miss, add to cache
        if len(cache_set) >= self.amt_ways:
            # Evict least recently used (last item)
            cache_set.pop(-1)
        cache_set.insert(0, (tag, value))

        if self.debug:
            print(f"Writing to cache: 0x{address:x}, value = {value}")
    
    def flush(self):
        self.cache = {i: [] for i in range(self.amt_sets)}
        if self.debug:
            print("Flushed complete cache")
    
    def flush_address(self, address):
        set_index = self.get_set_index(address)
        tag = self.get_tag(address)
        cache_set = self.cache[set_index]
        
        for i, (existing_tag, _) in enumerate(cache_set):
            if existing_tag == tag:
                cache_set.pop(i)
                if self.debug:
                    print(f"Flushed address 0x{address:x} from cache")
                return
        
        if self.debug:
            print(f"Address 0x{address:x} was not in cache, nothing to flush")
    
    def pretty_print(self, max_sets=None, data_preview_bytes=16):
        if max_sets is None:
            sets_to_print = self.amt_sets
        else:
            sets_to_print = min(max_sets, self.amt_sets)
            
        total_size_kb = (self.amt_sets * self.amt_ways * self.line_size) / 1024
        occupancy = sum(len(ways) for ways in self.cache.values())
        total_ways = self.amt_sets * self.amt_ways
        
        print(f"L1D Cache Status:")
        print(f"  Configuration: {self.amt_sets} sets x {self.amt_ways} ways x {self.line_size} bytes")
        print(f"  Total Size: {total_size_kb:.2f} KB")
        print(f"  Occupancy: {occupancy}/{total_ways} lines ({occupancy/total_ways*100:.1f}%)")
        print("-" * 80)
        
        for set_idx in range(sets_to_print):
            ways = self.cache[set_idx]
            if not ways and not self.debug:
                continue  # Skip empty sets unless in debug mode
                
            print(f"Set {set_idx:3d}: {len(ways)}/{self.amt_ways} ways occupied")
            
            for way_idx, (tag, data) in enumerate(ways):
                # Calculate the full address from tag and set
                addr = (tag * self.amt_sets + set_idx) * self.line_size
                
                # Convert data to hex representation for display
                if isinstance(data, bytes) or isinstance(data, bytearray):
                    # Preview the first few bytes of data
                    data_preview = binascii.hexlify(data[:data_preview_bytes]).decode()
                    if len(data) > data_preview_bytes:
                        data_preview += "..."
                else:
                    data_preview = str(data)
                    
                # LRU position (0 = Most Recently Used)
                print(f"  Way {way_idx:2d} (LRU {way_idx:2d}): Tag 0x{tag:x}, Addr 0x{addr:x}, Data: {data_preview}")
            
            print()
        
        if sets_to_print < self.amt_sets:
            print(f"... {self.amt_sets - sets_to_print} more sets ...")