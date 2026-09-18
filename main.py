import sys
from wfcr import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user. Exiting cleanly.")
        sys.exit(0)