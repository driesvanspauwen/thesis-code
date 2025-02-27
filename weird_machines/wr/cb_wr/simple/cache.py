class L1DCache:
    """
    A simple L1D cache model with LUR replacement policy
    """
    def __init__(self, sets=64, ways=8, line_size=64):
        """
        Args:
            sets: Number of cache sets (default: 64 for a typical L1D cache)
            ways: Number of ways per set (default: 8-way associative)
            line_size: Size of each cache line in bytes (default: 64 bytes)
        """
        self.sets = sets
        self.ways = ways
        self.line_size = line_size
        
        # Initialize cache structure as a dictionary of sets
        # Each set is a list of (tag, data) tuples representing the ways
        self.cache = {i: [] for i in range(sets)}
        
        # For weird register implementation
        self.weird_registers = {}
    
    def get_set_index(self, address) -> int:
        return (address // self.line_size) % self.sets
    
    def get_tag(self, address) -> int:
        return address // (self.line_size * self.sets)
    
    def read(self, address) -> int:
        set_index = self.get_set_index(address)
        tag = self.get_tag(address)
        cache_set = self.cache[set_index]

        for i, (existing_tag, data) in enumerate(cache_set):
            if existing_tag == tag:
                # Cache hit, move to start (MRU position)
                cache_set.insert(0, cache_set.pop(i))
                return data
        
        # Cache miss
        return None
    
    def write(self, address, value):
        set_idx = self.get_set_index(address)
        tag = self.get_tag(address)
        cache_set = self.cache[set_idx]

        for i, (existing_tag, data) in enumerate(cache_set):
            if existing_tag == tag:
                # Cache hit, remove old value and insert new at start (MRU position)
                cache_set.pop(i)
                cache_set.insert(0, (tag, value))
                return

        # Cache miss, add to cache
        if len(cache_set) >= self.ways:
            # Evict least recently used (last item)
            cache_set.pop(-1)
        cache_set.insert(0, (tag, value))
    
    def flush(self):
        self.cache = {i: [] for i in range(self.sets)}