import sys

PAGE_SIZE = 4096

def parse_line(line):
    # Example line format:
    # VA 0x400000 -> PA 0x366878000 - PTE flags: READ-ONLY ACCESSED
    parts = line.strip().split()
    try:
        va_index = parts.index("VA") + 1
        pa_index = parts.index("PA") + 1
        va = int(parts[va_index], 16)
        pa = int(parts[pa_index], 16)
        flags = " ".join(parts[pa_index+2:])
        return va, pa, flags
    except (ValueError, IndexError):
        return None

def print_block(start_va, start_pa, count):
    size = count * PAGE_SIZE
    print(f"Contiguous block: VA 0x{start_va:x} -> PA 0x{start_pa:x}, size {size} bytes ({count} pages)")

def main(filename):
    prev_va = None
    prev_pa = None
    start_va = None
    start_pa = None
    count = 0

    block_sizes = {}  # key: block size in pages, value: count of blocks

    with open(filename) as f:
        for line in f:
            parsed = parse_line(line)
            if not parsed:
                continue
            va, pa, flags = parsed

            if prev_va is None:
                # First entry
                start_va, start_pa = va, pa
                count = 1
            else:
                if va == prev_va + PAGE_SIZE and pa == prev_pa + PAGE_SIZE:
                    # contiguous
                    count += 1
                else:
                    # print previous block and record it
                    print_block(start_va, start_pa, count)
                    block_sizes[count] = block_sizes.get(count, 0) + 1
                    # start new block
                    start_va, start_pa = va, pa
                    count = 1

            prev_va, prev_pa = va, pa

    # print last block
    if count > 0:
        print_block(start_va, start_pa, count)
        block_sizes[count] = block_sizes.get(count, 0) + 1

    # Print summary
    print("\nSummary of contiguous block sizes:")
    for size in sorted(block_sizes.keys()):
        print(f"  {size} page(s): {block_sizes[size]} block(s)")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <page_table_dump_file>")
        sys.exit(1)
    main(sys.argv[1])
