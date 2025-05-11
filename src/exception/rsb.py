from typing import List

class RSB:
    def __init__(self):
        self.stack: List[int] = []
    
    def add_ret_addr(self, addr: int):
        self.stack.append(addr)
    
    def pop_ret_addr(self):
        return self.stack.pop()